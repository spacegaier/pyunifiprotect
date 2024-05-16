"""UniFi Protect session manager."""

from __future__ import annotations

import asyncio
import hashlib
from http.cookies import Morsel, SimpleCookie
import logging
from pathlib import Path
import re
import time
from typing import Any, cast

import aiofiles
from aiofiles import os as aos
from aiohttp import (
    ClientResponse,
    ClientSession,
    CookieJar,
    ServerDisconnectedError,
    client_exceptions,
)
import orjson
from platformdirs import user_cache_dir
from typing_extensions import TypedDict
from yarl import URL

from pyunifiprotect.exceptions import BadRequest, NotAuthorized, NvrError
from pyunifiprotect.utils import decode_token_cookie, get_response_reason

TOKEN_COOKIE_MAX_EXP_SECONDS = 60
_LOGGER = logging.getLogger(__name__)
_COOKIE_RE = re.compile(r"^set-cookie: ", re.IGNORECASE)

STORAGE_DIRECTORY = "ufp"


def get_user_hash(
    *,
    host: str,
    username: str,
    prefix: str | None = None,
) -> str:
    session = hashlib.sha256()
    if prefix:
        session.update(prefix.encode("utf8"))
    session.update(host.encode("utf8"))
    session.update(username.encode("utf8"))
    return session.hexdigest()


class SessionDict(TypedDict):
    auth_cookie: SimpleCookie
    csrf_token: str | None


class SessionCache:
    cache_dir: Path

    _lock: asyncio.Lock

    def __init__(self, *, cache_dir: Path | None = None) -> None:
        self.cache_dir = cache_dir or (Path(user_cache_dir()) / STORAGE_DIRECTORY)
        self._lock = asyncio.Lock()

    @property
    def session_cache(self) -> Path:

        return self.cache_dir / "sessions.json"

    async def read_session_cache(self) -> dict[str, Any] | None:
        """Read session cache."""

        cache: dict[str, Any] | None = None
        async with self._lock:
            try:
                async with aiofiles.open(self.session_cache, "rb") as f:
                    data = await f.read()
                    if data:
                        try:
                            cache = orjson.loads(data)
                        except Exception:
                            _LOGGER.warning("Invalid config file, ignoring.")
                            return None
            except FileNotFoundError:
                _LOGGER.debug("no config file, not loading session")
                return None

        return cache

    async def write_session_cache(self, sessions: dict[str, Any]) -> None:
        """Write session cache."""

        async with self._lock:
            await aos.makedirs(self.session_cache.parent, exist_ok=True)
            async with aiofiles.open(self.session_cache, "wb") as f:
                await f.write(orjson.dumps(sessions, option=orjson.OPT_INDENT_2))

    async def read_session(
        self,
        cookie_name: str,
        session_hash: str,
    ) -> SessionDict | None:
        """Read session cache and get specific session."""

        cache = await self.read_session_cache()
        if not cache:
            return None

        session = cache.get(session_hash)
        if not session:
            _LOGGER.debug("No existing session for %s", session_hash)
            return None

        cookie = SimpleCookie()
        cookie[cookie_name] = session.get("value")
        for key, value in session.get("metadata", {}).items():
            cookie[cookie_name][key] = value

        return {"auth_cookie": cookie, "csrf_token": session.get("csrf")}

    async def write_session(
        self,
        session_hash: str,
        auth_cookie: Morsel[str],
        csrf_token: str | None,
    ) -> None:
        """Write session to session cache."""

        cache = await self.read_session_cache()
        cache = cache or {}
        cache[session_hash] = {
            "metadata": dict(auth_cookie),
            "value": auth_cookie.value,
            "csrf": csrf_token,
        }

        await self.write_session_cache(cache)

    async def delete_session(self, session_hash: str) -> None:
        """Delete session from session cache."""

        cache = await self.read_session_cache()
        cache = cache or {}
        cache.pop(session_hash, None)
        await self.write_session_cache(cache)


class UnifiOSClient:
    _username: str
    _password: str
    _verify_ssl: bool
    _auth_lock: asyncio.Lock
    _url: URL
    _base_url: str

    _is_authenticated: bool = False
    _last_token_cookie: Morsel[str] | None = None
    _last_token_cookie_decode: dict[str, Any] | None = None
    _session: ClientSession | None = None
    _loaded_session: bool = False
    _version_prefix: str | None = None
    _auth_cookie_name: str | None = None

    headers: dict[str, str] | None = None

    session_cache: SessionCache | None = None

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        verify_ssl: bool = True,
        session: ClientSession | None = None,
        cache_dir: Path | None = None,
        store_sessions: bool = True,
    ) -> None:
        self._auth_lock = asyncio.Lock()

        self._username = username
        self._password = password
        self._verify_ssl = verify_ssl
        self._loaded_session = False

        if store_sessions:
            self.session_cache = SessionCache(cache_dir=cache_dir)

        if session is not None:
            self._session = session

        self.set_url(host, port)

    @property
    def url(self) -> URL:
        """Base URL for UniFi OS console."""

        return self._url

    def set_url(self, host: str, port: int) -> None:
        """Set base URL."""

        if port != 443:
            self._url = URL(f"https://{host}:{port}")
        else:
            self._url = URL(f"https://{host}")

        self._base_url = str(self._url)
        self._auth_cookie_name = None

    @property
    def base_url(self) -> str:
        """Base URL for UniFi OS console (str)."""

        return self._base_url

    @property
    def verify_ssl(self) -> bool:
        """Get if SSL connection is verified."""

        return self._verify_ssl

    async def get_version_prefix(self) -> str:
        """Get UniFi OS version prefix."""

        if self._version_prefix is not None:
            return self._version_prefix

        url = "/api/system"
        response = await self.request("get", url, auto_close=False)
        try:
            try:
                await self.verify_response(url, response)
            # try again with no authentication
            except NotAuthorized:
                return await self.get_version_prefix()

            data = await response.read()
        finally:
            response.release()

        json_data: list[Any] | dict[str, Any] = orjson.loads(data)
        if "debugEnabled" in json_data:
            self._version_prefix = "4"
        # unknown version / 3 or older
        else:
            self._version_prefix = ""

        return self._version_prefix

    async def get_auth_cookie_name(self) -> str:
        """Get UniFi OS auth cookie name."""

        if self._auth_cookie_name is None:
            prefix = await self.get_version_prefix()
            if prefix == "4":
                self._auth_cookie_name = "UOS_TOKEN"
            else:
                self._auth_cookie_name = "TOKEN"
        return self._auth_cookie_name

    async def get_session(self) -> ClientSession:
        """Gets or creates current client session"""

        if self._session is None or self._session.closed:
            if self._session is not None and self._session.closed:
                _LOGGER.debug("Session was closed, creating a new one")
            # need unsafe to access httponly cookies
            self._session = ClientSession(cookie_jar=CookieJar(unsafe=True))

        return self._session

    async def _load_cached_session(self) -> None:
        """Load cached session from disk."""

        if self._session is None:
            await self.get_session()
            assert self._session is not None

        self._loaded_session = True
        if not self.session_cache:
            return

        session_hash = get_user_hash(
            host=self.base_url,
            username=self._username,
            prefix=await self.get_version_prefix(),
        )
        cookie_name = await self.get_auth_cookie_name()
        session = await self.session_cache.read_session(cookie_name, session_hash)
        if not session:
            return

        if session.get("csrf_token"):
            self.set_header("x-csrf-token", session["csrf_token"])

        cookie = session["auth_cookie"]
        cookie_value = _COOKIE_RE.sub("", str(cookie[cookie_name]))
        self._last_token_cookie = cookie[cookie_name]
        self._last_token_cookie_decode = None
        self._is_authenticated = True
        self.set_header("cookie", cookie_value)
        _LOGGER.debug("Successfully loaded session from config")
        self._session.cookie_jar.update_cookies(cookie)

    async def close_session(self) -> None:
        """Closing and delets client session"""

        if self._session is not None:
            await self._session.close()
            self._session = None
            self._loaded_session = False

    def set_header(self, key: str, value: str | None) -> None:
        """Set header."""

        self.headers = self.headers or {}
        if value is None:
            self.headers.pop(key, None)
        else:
            self.headers[key] = value

    async def verify_response(self, url: str, response: ClientResponse) -> None:
        """Verify the response from UniFi OS is a non-error."""

        if response.status != 200:
            reason = await get_response_reason(response)
            msg = "Request failed: %s - Status: %s - Reason: %s"
            if response.status in {401, 403}:
                await self.clear_auth()
                raise NotAuthorized(msg % (url, response.status, reason))
            if response.status >= 400 and response.status < 500:
                raise BadRequest(msg % (url, response.status, reason))
            raise NvrError(msg % (url, response.status, reason))

    async def request(
        self,
        method: str,
        url: str,
        require_auth: bool = False,
        auto_close: bool = True,
        **kwargs: Any,
    ) -> ClientResponse:
        """Make a request to UniFi OS console."""

        if require_auth:
            await self.ensure_authenticated()

        request_url = self._url.joinpath(url[1:])
        headers = kwargs.get("headers") or self.headers
        _LOGGER.debug("Request url: %s", request_url)
        if not self._verify_ssl:
            kwargs["ssl"] = False
        session = await self.get_session()

        for attempt in range(2):
            try:
                req_context = session.request(
                    method,
                    request_url,
                    headers=headers,
                    **kwargs,
                )
                response = await req_context.__aenter__()  # noqa: PLC2801

                await self._update_last_token_cookie(response, require=require_auth)
                if auto_close:
                    try:
                        _LOGGER.debug(
                            "%s %s %s",
                            response.status,
                            response.content_type,
                            response,
                        )
                        response.release()
                    except Exception:
                        # make sure response is released
                        response.release()
                        # re-raise exception
                        raise

                return response
            except ServerDisconnectedError as err:
                # If the server disconnected, try again
                # since HTTP/1.1 allows the server to disconnect
                # at any time
                if attempt == 0:
                    continue
                raise NvrError(
                    f"Error requesting data from {self._base_url}: {err}",
                ) from err
            except client_exceptions.ClientError as err:
                raise NvrError(
                    f"Error requesting data from {self._base_url}: {err}",
                ) from err

        # should never happen
        raise NvrError(f"Error requesting data from {self._base_url}")

    async def ensure_authenticated(self) -> None:
        """Ensure we are authenticated."""

        if not self._loaded_session and self.session_cache:
            await self._load_cached_session()

        if self.is_authenticated() is False:
            await self.authenticate()

    async def clear_auth(self) -> None:
        """Clear authentication."""

        if self._session is not None:
            self._session.cookie_jar.clear()
        self.set_header("cookie", None)
        self.set_header("x-csrf-token", None)

        if self._version_prefix and self.session_cache:
            session_hash = get_user_hash(
                host=self.base_url,
                username=self._username,
                prefix=self._version_prefix,
            )
            await self.session_cache.delete_session(session_hash)

    async def authenticate(self) -> None:
        """Authenticate and get a token."""
        if self._auth_lock.locked():
            # If an auth is already in progress
            # do not start another one
            async with self._auth_lock:
                return

        async with self._auth_lock:
            url = "/api/auth/login"

            if self._session is not None:
                self._session.cookie_jar.clear()
                self.set_header("cookie", None)

            auth = {
                "username": self._username,
                "password": self._password,
                "rememberMe": self.session_cache is not None,
            }

            response = await self.request("post", url=url, json=auth)
            self.set_header("cookie", response.headers.get("set-cookie", ""))
            self._is_authenticated = True
            await self._update_last_token_cookie(response)
            _LOGGER.debug("Authenticated successfully!")

    async def _update_last_token_cookie(
        self,
        response: ClientResponse,
        *,
        require: bool = True,
    ) -> None:
        """Update the last token cookie."""

        update_cache = False
        csrf_token = response.headers.get("x-csrf-token")
        if (
            csrf_token is not None
            and self.headers
            and csrf_token != self.headers.get("x-csrf-token")
        ):
            self.set_header("x-csrf-token", csrf_token)
            update_cache = True

        if self._version_prefix is None:
            if require:
                raise BadRequest(
                    "Authenticated request made before auth cookie is loaded.",
                )
            return

        token_cookie = response.cookies.get(await self.get_auth_cookie_name())
        if token_cookie and token_cookie != self._last_token_cookie:
            self._last_token_cookie = token_cookie
            self._last_token_cookie_decode = None
            update_cache = True

        token_cookie = token_cookie or self._last_token_cookie
        if token_cookie and update_cache and self.session_cache:
            session_hash = get_user_hash(
                host=self.base_url,
                username=self._username,
                prefix=await self.get_version_prefix(),
            )
            await self.session_cache.write_session(
                session_hash,
                token_cookie,
                csrf_token,
            )

    def is_authenticated(self) -> bool:
        """Check to see if we are already authenticated."""
        if self._session is None:
            return False

        if self._is_authenticated is False:
            return False

        if self._last_token_cookie is None:
            return False

        # Lazy decode the token cookie
        if self._last_token_cookie and self._last_token_cookie_decode is None:
            self._last_token_cookie_decode = decode_token_cookie(
                self._last_token_cookie,
            )

        if (
            self._last_token_cookie_decode is None
            or "exp" not in self._last_token_cookie_decode
        ):
            return False

        token_expires_at = cast(int, self._last_token_cookie_decode["exp"])
        max_expire_time = time.time() + TOKEN_COOKIE_MAX_EXP_SECONDS

        return token_expires_at >= max_expire_time
