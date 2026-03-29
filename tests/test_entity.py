"""Unit tests for Nest Yale entity device-registry updates."""

from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import ModuleType, SimpleNamespace
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPO_ROOT / "custom_components"
MODULE_PATH = PACKAGE_ROOT / "nest_yale_lock" / "entity.py"


def _install_homeassistant_stubs() -> None:
    homeassistant_pkg = sys.modules.setdefault("homeassistant", ModuleType("homeassistant"))
    homeassistant_pkg.__path__ = []

    helpers_pkg = sys.modules.setdefault(
        "homeassistant.helpers",
        ModuleType("homeassistant.helpers"),
    )
    helpers_pkg.__path__ = []

    update_coordinator_mod = sys.modules.setdefault(
        "homeassistant.helpers.update_coordinator",
        ModuleType("homeassistant.helpers.update_coordinator"),
    )
    if not hasattr(update_coordinator_mod, "CoordinatorEntity"):
        class CoordinatorEntity:
            def __init__(self, coordinator):
                self.coordinator = coordinator
                self.hass = getattr(coordinator, "hass", None)

            async def async_added_to_hass(self):
                return None

            def async_write_ha_state(self):
                return None

        update_coordinator_mod.CoordinatorEntity = CoordinatorEntity

    device_registry_mod = sys.modules.setdefault(
        "homeassistant.helpers.device_registry",
        ModuleType("homeassistant.helpers.device_registry"),
    )
    if not hasattr(device_registry_mod, "DeviceInfo"):
        class DeviceInfo(dict):
            """Lightweight DeviceInfo stub for unit tests."""

        device_registry_mod.DeviceInfo = DeviceInfo
    device_registry_mod.async_get = lambda hass: hass.device_registry

    entity_registry_mod = sys.modules.setdefault(
        "homeassistant.helpers.entity_registry",
        ModuleType("homeassistant.helpers.entity_registry"),
    )
    entity_registry_mod.async_get = lambda hass: hass.entity_registry


_install_homeassistant_stubs()

custom_components_pkg = sys.modules.setdefault("custom_components", ModuleType("custom_components"))
custom_components_pkg.__path__ = [str(PACKAGE_ROOT)]

nest_pkg = sys.modules.setdefault(
    "custom_components.nest_yale_lock",
    ModuleType("custom_components.nest_yale_lock"),
)
nest_pkg.__path__ = [str(PACKAGE_ROOT / "nest_yale_lock")]

SPEC = spec_from_file_location("custom_components.nest_yale_lock.entity", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load entity module from {MODULE_PATH}")
ENTITY_MODULE = module_from_spec(SPEC)
sys.modules[SPEC.name] = ENTITY_MODULE
SPEC.loader.exec_module(ENTITY_MODULE)

NestYaleEntity = ENTITY_MODULE.NestYaleEntity
DOMAIN = ENTITY_MODULE.DOMAIN
_has_defined_value = ENTITY_MODULE._has_defined_value


class FakeApiClient:
    def __init__(self, metadata: dict):
        self._metadata = metadata
        self.user_id = None
        self.structure_id = None

    def get_device_metadata(self, device_id):
        del device_id
        return self._metadata.copy()


class FakeCoordinator:
    def __init__(self, metadata: dict, data: dict | None = None):
        self.api_client = FakeApiClient(metadata)
        self.data = data or {}
        self.debug_attributes_enabled = False
        self.hass = None
        self._stale_max_seconds = 900

    def last_good_update_age(self):
        return None


class FakeDeviceRegistry:
    def __init__(self, device):
        self._device = device
        self.updated_calls: list[tuple[str, dict]] = []

    def async_get_device(self, identifiers):
        del identifiers
        return self._device

    def async_update_device(self, device_id, **kwargs):
        self.updated_calls.append((device_id, kwargs))
        for key, value in kwargs.items():
            setattr(self._device, key, value)


class FakeEntityRegistry:
    def async_get(self, entity_id):
        del entity_id
        return None


class TestNestYaleEntity(unittest.TestCase):
    def _make_entity(self, *, door_label="Front Door", where_label="Entryway"):
        coordinator = FakeCoordinator(
            metadata={
                "name": "Lock",
                "firmware_revision": "1.0",
                "serial_number": "SERIAL_1",
            },
            data={
                "DEVICE_1": {
                    "device_id": "DEVICE_1",
                    "door_label": door_label,
                    "where_label": where_label,
                    "traits": {},
                }
            },
        )
        entity = NestYaleEntity(
            coordinator,
            "DEVICE_1",
            coordinator.data["DEVICE_1"],
        )
        return coordinator, entity

    @staticmethod
    def _attach_hass(entity, device):
        registry = FakeDeviceRegistry(device)
        entity.hass = SimpleNamespace(
            device_registry=registry,
            entity_registry=FakeEntityRegistry(),
        )
        return registry

    def test_where_label_change_does_not_trigger_registry_update(self):
        _, entity = self._make_entity()
        device = SimpleNamespace(
            id="registry-device",
            name="Front Door",
            name_by_user=None,
            sw_version="1.0",
            manufacturer="Nest",
            model="Nest x Yale Lock",
            serial_number="SERIAL_1",
            area_id=None,
            identifiers={(DOMAIN, "DEVICE_1")},
        )
        registry = self._attach_hass(entity, device)

        entity._device_data["where_label"] = "Garage"
        entity._update_device_name_from_data()

        self.assertEqual([], registry.updated_calls)
        self.assertEqual("Garage", entity._where_label)
        self.assertIsNone(device.area_id)

    def test_manual_area_assignment_persists_when_name_changes(self):
        coordinator, entity = self._make_entity()
        device = SimpleNamespace(
            id="registry-device",
            name="Front Door",
            name_by_user=None,
            sw_version="1.0",
            manufacturer="Nest",
            model="Nest x Yale Lock",
            serial_number="SERIAL_1",
            area_id="manual-area",
            identifiers={(DOMAIN, "DEVICE_1")},
        )
        registry = self._attach_hass(entity, device)

        coordinator.data["DEVICE_1"] = {
            "device_id": "DEVICE_1",
            "door_label": "Side Door",
            "where_label": "Garage",
            "traits": {},
        }

        entity._apply_coordinator_update()

        self.assertEqual(1, len(registry.updated_calls))
        _, update_kwargs = registry.updated_calls[0]
        self.assertEqual({"name": "Side Door"}, update_kwargs)
        self.assertNotIn("area_id", update_kwargs)
        self.assertEqual("manual-area", device.area_id)
        self.assertEqual("Side Door", entity._device_name)
        self.assertEqual("Garage", entity._where_label)

    def test_build_device_registry_updates_only_name_without_area_sync(self):
        _, entity = self._make_entity(door_label="Side Door", where_label="Kitchen")
        device = SimpleNamespace(
            id="registry-device",
            name="Front Door",
            name_by_user=None,
            sw_version="1.0",
            manufacturer="Nest",
            model="Nest x Yale Lock",
            serial_number="SERIAL_1",
            area_id="existing-area",
            identifiers={(DOMAIN, "DEVICE_1")},
        )

        update_kwargs = entity._build_device_registry_updates(
            device,
            None,
            None,
            None,
            None,
        )

        self.assertEqual({"name": "Side Door"}, update_kwargs)
        self.assertNotIn("area_id", update_kwargs)

    def test_base_entity_available_uses_stream_health(self):
        _, entity = self._make_entity()

        self.assertTrue(entity.available)

        entity._coordinator.last_good_update_age = lambda: 901
        entity._coordinator.hass = SimpleNamespace(data={})

        self.assertFalse(entity.available)

    def test_has_defined_value_requires_non_null_source_field(self):
        self.assertTrue(_has_defined_value({"last_action": "Physical"}, "last_action"))
        self.assertFalse(_has_defined_value({"last_action": None}, "last_action"))
        self.assertFalse(_has_defined_value({}, "last_action"))


if __name__ == "__main__":
    unittest.main()
