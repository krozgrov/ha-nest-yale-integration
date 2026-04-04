"""Regression tests for shared protobuf coexistence."""

from __future__ import annotations

import importlib.util
from importlib import import_module
from pathlib import Path
import sys
import types
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPO_ROOT / "custom_components"


def _clear_modules(*prefixes: str) -> None:
    for module_name in list(sys.modules):
        if any(
            module_name == prefix or module_name.startswith(f"{prefix}.")
            for prefix in prefixes
        ):
            sys.modules.pop(module_name, None)


def _ensure_package(name: str, path: str | None = None) -> types.ModuleType:
    module = sys.modules.get(name)
    if module is None:
        module = types.ModuleType(name)
        sys.modules[name] = module
    module.__path__ = [path] if path else []
    return module


def _stub_class(name: str, **attrs):
    return type(name, (), attrs)


def _install_repo_packages() -> None:
    _ensure_package("custom_components", str(PACKAGE_ROOT))
    _ensure_package(
        "custom_components.nest_yale_lock",
        str(PACKAGE_ROOT / "nest_yale_lock"),
    )


def _install_fake_legacy_proto_modules() -> dict[str, types.ModuleType]:
    _ensure_package("custom_components.nest_legacy")
    _ensure_package("custom_components.nest_legacy.pynest")
    _ensure_package("custom_components.nest_legacy.pynest.protobuf_gen")
    _ensure_package("custom_components.nest_legacy.pynest.protobuf_gen.weave")
    _ensure_package("custom_components.nest_legacy.pynest.protobuf_gen.weave.trait")
    _ensure_package("custom_components.nest_legacy.pynest.protobuf_gen.nest")
    _ensure_package("custom_components.nest_legacy.pynest.protobuf_gen.nest.trait")
    _ensure_package("custom_components.nest_legacy.pynest.protobuf_gen.nestlabs")
    _ensure_package("custom_components.nest_legacy.pynest.protobuf_gen.nestlabs.gateway")

    modules: dict[str, types.ModuleType] = {}

    def _install(name: str, **attrs) -> types.ModuleType:
        module = types.ModuleType(name)
        for key, value in attrs.items():
            setattr(module, key, value)
        sys.modules[name] = module
        modules[name] = module
        return module

    _install(
        "custom_components.nest_legacy.pynest.protobuf_gen.weave.trait.security_pb2",
        BoltLockTrait=_stub_class("BoltLockTrait"),
        BoltLockSettingsTrait=_stub_class("BoltLockSettingsTrait"),
        BoltLockCapabilitiesTrait=_stub_class("BoltLockCapabilitiesTrait"),
        UserPincodesSettingsTrait=_stub_class("UserPincodesSettingsTrait"),
        UserPincodesCapabilitiesTrait=_stub_class("UserPincodesCapabilitiesTrait"),
        TamperTrait=_stub_class("TamperTrait"),
        PincodeInputTrait=_stub_class("PincodeInputTrait"),
    )
    _install(
        "custom_components.nest_legacy.pynest.protobuf_gen.nest.trait.security_pb2",
        EnhancedBoltLockSettingsTrait=_stub_class("EnhancedBoltLockSettingsTrait"),
    )
    _install(
        "custom_components.nest_legacy.pynest.protobuf_gen.nest.trait.structure_pb2",
        StructureInfoTrait=_stub_class("StructureInfoTrait"),
    )
    _install(
        "custom_components.nest_legacy.pynest.protobuf_gen.nest.trait.located_pb2",
        DeviceLocatedSettingsTrait=_stub_class("DeviceLocatedSettingsTrait"),
        LocatedAnnotationsTrait=_stub_class("LocatedAnnotationsTrait"),
        LocatedTrait=_stub_class("LocatedTrait", LOCATED_MAJOR_FIXTURE_TYPE_DOOR=1),
    )
    _install(
        "custom_components.nest_legacy.pynest.protobuf_gen.nest.rpc_pb2",
        StreamBody=_stub_class("StreamBody"),
    )
    _install(
        "custom_components.nest_legacy.pynest.protobuf_gen.nestlabs.gateway.v1_pb2",
        SendCommandResponse=_stub_class("SendCommandResponse"),
        ResourceCommand=_stub_class("ResourceCommand"),
        SendCommandRequest=_stub_class("SendCommandRequest"),
        ResourceRequest=_stub_class("ResourceRequest"),
    )
    _install(
        "custom_components.nest_legacy.pynest.protobuf_gen.weave.trait.description_pb2",
        DeviceIdentityTrait=_stub_class("DeviceIdentityTrait"),
        LabelSettingsTrait=_stub_class("LabelSettingsTrait"),
    )
    _install(
        "custom_components.nest_legacy.pynest.protobuf_gen.weave.trait.power_pb2",
        BatteryPowerSourceTrait=_stub_class("BatteryPowerSourceTrait"),
    )

    return modules


def _install_runtime_stubs() -> None:
    homeassistant_pkg = sys.modules.setdefault("homeassistant", types.ModuleType("homeassistant"))
    config_entries_pkg = sys.modules.setdefault(
        "homeassistant.config_entries",
        types.ModuleType("homeassistant.config_entries"),
    )
    core_pkg = sys.modules.setdefault("homeassistant.core", types.ModuleType("homeassistant.core"))
    helpers_pkg = sys.modules.setdefault("homeassistant.helpers", types.ModuleType("homeassistant.helpers"))
    aiohttp_client_pkg = sys.modules.setdefault(
        "homeassistant.helpers.aiohttp_client",
        types.ModuleType("homeassistant.helpers.aiohttp_client"),
    )
    exceptions_pkg = sys.modules.setdefault(
        "homeassistant.exceptions",
        types.ModuleType("homeassistant.exceptions"),
    )
    voluptuous_pkg = sys.modules.setdefault("voluptuous", types.ModuleType("voluptuous"))
    aiohttp_pkg = sys.modules.setdefault("aiohttp", types.ModuleType("aiohttp"))
    jwt_pkg = sys.modules.setdefault("jwt", types.ModuleType("jwt"))

    class _ConfigFlow:
        def __init_subclass__(cls, **kwargs):
            return super().__init_subclass__()

    class _OptionsFlow:
        pass

    class _ConfigEntry:
        pass

    class _ClientError(Exception):
        pass

    class _ClientResponseError(_ClientError):
        def __init__(self, *args, status=None, message="", headers=None, **kwargs):
            super().__init__(message or f"status={status}")
            self.status = status
            self.message = message
            self.headers = headers

    class _ClientTimeout:
        def __init__(self, total=None):
            self.total = total

    class _ClientSession:
        pass

    class _ConfigEntryAuthFailed(Exception):
        pass

    def _callback(func):
        return func

    config_entries_pkg.ConfigFlow = _ConfigFlow
    config_entries_pkg.OptionsFlow = _OptionsFlow
    config_entries_pkg.ConfigEntry = _ConfigEntry
    core_pkg.callback = _callback
    aiohttp_client_pkg.async_get_clientsession = lambda _hass: None
    exceptions_pkg.ConfigEntryAuthFailed = _ConfigEntryAuthFailed
    homeassistant_pkg.config_entries = config_entries_pkg
    homeassistant_pkg.core = core_pkg
    homeassistant_pkg.helpers = helpers_pkg
    helpers_pkg.aiohttp_client = aiohttp_client_pkg
    homeassistant_pkg.exceptions = exceptions_pkg
    voluptuous_pkg.Schema = lambda value: value
    voluptuous_pkg.Required = lambda value, default=None: value
    voluptuous_pkg.Optional = lambda value, default=None: value
    voluptuous_pkg.All = lambda *validators: validators[-1] if validators else None
    voluptuous_pkg.Coerce = lambda _type: _type
    voluptuous_pkg.Range = lambda **kwargs: kwargs
    aiohttp_pkg.ClientError = _ClientError
    aiohttp_pkg.ClientResponseError = _ClientResponseError
    aiohttp_pkg.ClientTimeout = _ClientTimeout
    aiohttp_pkg.ClientSession = _ClientSession
    jwt_pkg.decode = lambda *args, **kwargs: {}


def _install_google_rpc_status_alias() -> types.ModuleType:
    google_pkg = import_module("google")
    import_module("google.protobuf")

    rpc_pkg = types.ModuleType("google.rpc")
    rpc_pkg.__path__ = []
    sys.modules["google.rpc"] = rpc_pkg
    google_pkg.rpc = rpc_pkg

    module_name = "google.rpc.status_pb2"
    module_path = (
        PACKAGE_ROOT / "nest_yale_lock" / "proto" / "zzzgoogle" / "rpc" / "status_pb2.py"
    )
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise AssertionError("Unable to build test spec for google.rpc.status_pb2")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    rpc_pkg.status_pb2 = module
    return module


class TestProtobufCompat(unittest.TestCase):
    def setUp(self) -> None:
        _clear_modules(
            "custom_components.nest_yale_lock.protobuf_compat",
            "custom_components.nest_yale_lock.protobuf_handler",
            "custom_components.nest_yale_lock.api_client",
            "custom_components.nest_yale_lock.config_flow",
            "custom_components.nest_yale_lock.proto",
            "custom_components.nest_legacy",
            "google.rpc",
            "homeassistant",
            "aiohttp",
            "jwt",
        )
        _install_repo_packages()

    def test_prefers_shared_modules_when_available(self) -> None:
        fake_modules = _install_fake_legacy_proto_modules()

        compat = import_module("custom_components.nest_yale_lock.protobuf_compat")

        self.assertIs(
            fake_modules[
                "custom_components.nest_legacy.pynest.protobuf_gen.weave.trait.security_pb2"
            ],
            compat.load_weave_trait_security_pb2(),
        )
        self.assertIs(
            fake_modules[
                "custom_components.nest_legacy.pynest.protobuf_gen.nestlabs.gateway.v1_pb2"
            ],
            compat.load_nestlabs_gateway_v1_pb2(),
        )

    def test_falls_back_to_local_modules_without_shared_install(self) -> None:
        _install_google_rpc_status_alias()
        compat = import_module("custom_components.nest_yale_lock.protobuf_compat")

        weave_security_pb2 = compat.load_weave_trait_security_pb2()
        v1_pb2 = compat.load_nestlabs_gateway_v1_pb2()

        self.assertEqual(
            "custom_components.nest_yale_lock.proto.weave.trait.security_pb2",
            weave_security_pb2.__name__,
        )
        self.assertEqual(
            "custom_components.nest_yale_lock.proto.nestlabs.gateway.v1_pb2",
            v1_pb2.__name__,
        )

    def test_config_flow_import_uses_shared_modules_and_avoids_local_proto_loads(self) -> None:
        fake_modules = _install_fake_legacy_proto_modules()
        _install_runtime_stubs()

        config_flow = import_module("custom_components.nest_yale_lock.config_flow")

        self.assertIsNotNone(config_flow)
        api_client = sys.modules["custom_components.nest_yale_lock.api_client"]
        protobuf_handler = sys.modules["custom_components.nest_yale_lock.protobuf_handler"]
        self.assertIs(
            fake_modules[
                "custom_components.nest_legacy.pynest.protobuf_gen.weave.trait.security_pb2"
            ],
            api_client.weave_security_pb2,
        )
        self.assertIs(
            fake_modules[
                "custom_components.nest_legacy.pynest.protobuf_gen.weave.trait.security_pb2"
            ],
            protobuf_handler.weave_security_pb2,
        )
        self.assertIs(
            fake_modules[
                "custom_components.nest_legacy.pynest.protobuf_gen.nestlabs.gateway.v1_pb2"
            ],
            api_client.v1_pb2,
        )
        self.assertNotIn(
            "custom_components.nest_yale_lock.proto.weave.common_pb2",
            sys.modules,
        )
        self.assertNotIn(
            "custom_components.nest_yale_lock.proto.weave.trait.security_pb2",
            sys.modules,
        )

    def test_local_gateway_import_uses_runtime_google_rpc_status(self) -> None:
        runtime_status_pb2 = _install_google_rpc_status_alias()

        gateway_v1 = import_module(
            "custom_components.nest_yale_lock.proto.nestlabs.gateway.v1_pb2"
        )

        self.assertIsNotNone(gateway_v1)
        self.assertIs(
            runtime_status_pb2,
            gateway_v1.google_dot_rpc_dot_status__pb2,
        )
        self.assertNotIn(
            "custom_components.nest_yale_lock.proto.zzzgoogle.rpc.status_pb2",
            sys.modules,
        )


if __name__ == "__main__":
    unittest.main()
