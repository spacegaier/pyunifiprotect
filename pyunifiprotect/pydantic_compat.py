"""pydantic compatibility layer."""

from __future__ import annotations

from importlib.metadata import version
from typing import TYPE_CHECKING

from packaging.version import Version

__all__ = [
    "SHAPE_DICT",
    "SHAPE_LIST",
    "SHAPE_SET",
    "BaseConfig",
    "BaseModel",
    "Color",
    "ConstrainedFloat",
    "ConstrainedInt",
    "ConstrainedStr",
    "ModelField",
    "PrivateAttr",
    "ValidationError",
    "to_camel",
]

_pydantic_version = Version(version("pydantic"))
# 1.10.15 has a broken `pydantic.v1` interface / fixed in 1.10.16
_min_version = Version("1.10.16")
_is_v1 = _pydantic_version < _min_version


if not _is_v1:
    from pydantic.v1 import (
        BaseConfig,
        BaseModel,
        ConstrainedFloat,
        ConstrainedInt,
        ConstrainedStr,
        ValidationError,
    )
    from pydantic.v1.color import Color
    from pydantic.v1.fields import (
        SHAPE_DICT,
        SHAPE_LIST,
        SHAPE_SET,
        ModelField,
        PrivateAttr,
    )
    from pydantic.v1.utils import to_camel
else:
    from pydantic import (  # type: ignore[assignment]
        BaseConfig,
        BaseModel,
        ConstrainedFloat,
        ConstrainedInt,
        ConstrainedStr,
        ValidationError,
    )
    from pydantic.color import Color  # type: ignore[assignment]
    from pydantic.fields import (  # type: ignore[attr-defined]
        SHAPE_DICT,
        SHAPE_LIST,
        SHAPE_SET,
        ModelField,
        PrivateAttr,
    )
    from pydantic.utils import to_camel

if TYPE_CHECKING:
    if _is_v1:
        from pydantic.typing import DictStrAny, SetStr
    else:
        from pydantic.v1.typing import DictStrAny, SetStr  # noqa: F401
