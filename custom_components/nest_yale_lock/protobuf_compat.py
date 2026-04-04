"""Compatibility helpers for shared protobuf modules.

This integration can coexist with other custom Nest integrations that ship
generated protobuf modules for the same ``weave.*`` / ``nest.*`` packages.
Those generated files all register descriptors into protobuf's global default
descriptor pool, so importing two copies under different module paths raises
duplicate symbol errors. Prefer reusing an already-installed shared protobuf
tree when available, and fall back to the local generated modules otherwise.

Do not route ``google.*`` proto imports through this compatibility layer.
Well-known Google descriptors must come from the runtime-installed modules so
Home Assistant integrations can share the same descriptor pool safely.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import import_module
import logging
from types import ModuleType

_LOGGER = logging.getLogger(__name__)

_SHARED_PROTO_ROOTS = (
    "custom_components.nest_legacy.pynest.protobuf_gen",
)
_LOCAL_PROTO_ROOT = "custom_components.nest_yale_lock.proto"


def _missing_within_root(exc: ModuleNotFoundError, module_name: str, root: str) -> bool:
    """Return True when the import failed because the target tree is absent."""
    missing = getattr(exc, "name", "") or ""
    if not missing:
        return False
    return (
        missing == module_name
        or module_name.startswith(f"{missing}.")
        or missing.startswith(f"{root}.")
    )


@lru_cache(maxsize=None)
def _load_proto_module(relative_name: str) -> ModuleType:
    """Load a protobuf module, preferring an installed shared protobuf tree."""
    candidates = [
        (f"{root}.{relative_name}", root) for root in _SHARED_PROTO_ROOTS
    ]
    candidates.append((f"{_LOCAL_PROTO_ROOT}.{relative_name}", _LOCAL_PROTO_ROOT))
    last_error: Exception | None = None

    for module_name, root in candidates:
        try:
            module = import_module(module_name)
        except ModuleNotFoundError as err:
            if _missing_within_root(err, module_name, root):
                last_error = err
                continue
            raise
        except Exception as err:
            last_error = err
            if root != _LOCAL_PROTO_ROOT:
                _LOGGER.debug(
                    "Unable to import shared protobuf module %s; using local fallback",
                    module_name,
                    exc_info=err,
                )
                continue
            raise
        else:
            if root != _LOCAL_PROTO_ROOT:
                _LOGGER.debug("Using shared protobuf module %s", module_name)
            return module

    if last_error is not None:
        raise last_error

    raise ModuleNotFoundError(relative_name)


def load_weave_trait_security_pb2() -> ModuleType:
    return _load_proto_module("weave.trait.security_pb2")


def load_nest_trait_security_pb2() -> ModuleType:
    return _load_proto_module("nest.trait.security_pb2")


def load_nest_trait_structure_pb2() -> ModuleType:
    return _load_proto_module("nest.trait.structure_pb2")


def load_nest_trait_located_pb2() -> ModuleType:
    return _load_proto_module("nest.trait.located_pb2")


def load_nest_rpc_pb2() -> ModuleType:
    return _load_proto_module("nest.rpc_pb2")


def load_nestlabs_gateway_v1_pb2() -> ModuleType:
    return _load_proto_module("nestlabs.gateway.v1_pb2")


def load_weave_trait_description_pb2() -> ModuleType:
    return _load_proto_module("weave.trait.description_pb2")


def load_weave_trait_power_pb2() -> ModuleType:
    return _load_proto_module("weave.trait.power_pb2")
