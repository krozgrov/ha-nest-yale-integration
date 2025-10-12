"""Expose generated protobuf modules and helpers for the Nest Yale integration."""

from importlib import import_module
from pathlib import Path
from types import ModuleType
from typing import Dict
import sys

PACKAGE_PATH = Path(__file__).resolve().parent

__all__ = ["PACKAGE_PATH", "const"]

try:
    const = import_module(".const", __name__)
except ModuleNotFoundError:  # pragma: no cover - optional helper module
    const = None


def _ensure_namespace(alias: str) -> ModuleType:
    """Ensure a namespace package exists for a given alias."""
    module = sys.modules.get(alias)
    if module is None:
        module = ModuleType(alias)
        module.__path__ = [str(PACKAGE_PATH)]
        sys.modules[alias] = module
        parent_name, _, attr = alias.rpartition(".")
        if parent_name:
            parent = _ensure_namespace(parent_name)
            setattr(parent, attr, module)
    else:
        paths = getattr(module, "__path__", [])
        if str(PACKAGE_PATH) not in paths:
            if isinstance(paths, list):
                paths.append(str(PACKAGE_PATH))
            else:  # pragma: no cover - defensive
                module.__path__ = [str(PACKAGE_PATH)]
    return module


def _alias_modules(mapping: Dict[str, str]) -> None:
    """Register import aliases so generated protobuf modules can resolve legacy paths."""
    for alias, target in mapping.items():
        module = sys.modules.get(alias)
        if module is None:
            module = import_module(target)
            sys.modules[alias] = module
        parent_name, _, attr = alias.rpartition(".")
        if parent_name:
            parent = sys.modules.get(parent_name)
            if parent is None:
                parent = _ensure_namespace(parent_name)
            setattr(parent, attr, module)


_ensure_namespace("proto")

BASE = __name__

_alias_modules({
    "proto.nest": f"{BASE}.nest",
    "proto.nest.iface_pb2": f"{BASE}.nest.iface_pb2",
    "proto.nest.messages_pb2": f"{BASE}.nest.messages_pb2",
    "proto.nest.rpc_pb2": f"{BASE}.nest.rpc_pb2",
    "proto.nest.trait": f"{BASE}.nest.trait",
    "proto.nest.trait.detector_pb2": f"{BASE}.nest.trait.detector_pb2",
    "proto.nest.trait.hvac_pb2": f"{BASE}.nest.trait.hvac_pb2",
    "proto.nest.trait.located_pb2": f"{BASE}.nest.trait.located_pb2",
    "proto.nest.trait.occupancy_pb2": f"{BASE}.nest.trait.occupancy_pb2",
    "proto.nest.trait.security_pb2": f"{BASE}.nest.trait.security_pb2",
    "proto.nest.trait.sensor_pb2": f"{BASE}.nest.trait.sensor_pb2",
    "proto.nest.trait.structure_pb2": f"{BASE}.nest.trait.structure_pb2",
    "proto.nest.trait.user_pb2": f"{BASE}.nest.trait.user_pb2",
    "proto.nestlabs": f"{BASE}.nestlabs",
    "proto.nestlabs.gateway": f"{BASE}.nestlabs.gateway",
    "proto.nestlabs.gateway.v1_pb2": f"{BASE}.nestlabs.gateway.v1_pb2",
    "proto.nestlabs.gateway.v2_pb2": f"{BASE}.nestlabs.gateway.v2_pb2",
    "proto.weave": f"{BASE}.weave",
    "proto.weave.common_pb2": f"{BASE}.weave.common_pb2",
    "proto.weave.trait": f"{BASE}.weave.trait",
    "proto.weave.trait.description_pb2": f"{BASE}.weave.trait.description_pb2",
    "proto.weave.trait.heartbeat_pb2": f"{BASE}.weave.trait.heartbeat_pb2",
    "proto.weave.trait.peerdevices_pb2": f"{BASE}.weave.trait.peerdevices_pb2",
    "proto.weave.trait.power_pb2": f"{BASE}.weave.trait.power_pb2",
    "proto.weave.trait.security_pb2": f"{BASE}.weave.trait.security_pb2",
})
