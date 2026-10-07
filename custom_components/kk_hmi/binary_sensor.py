"""Binary sensors: grid, backup, generator relay and the PICMK link."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from homeassistant.components.binary_sensor import (BinarySensorDeviceClass, BinarySensorEntity,
                                                    BinarySensorEntityDescription)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import KkCoordinator
from .entity import KkEntity
from .model import KkState


@dataclass(frozen=True, kw_only=True)
class KkBinaryDescription(BinarySensorEntityDescription):
    value_fn: Callable[[KkState], bool | None]
    needs_live_link: bool = True


DESCRIPTIONS: tuple[KkBinaryDescription, ...] = (
    KkBinaryDescription(key="grid_present", name="Grid present", device_class=BinarySensorDeviceClass.POWER,
                        value_fn=lambda s: s.mode_value("grid_present")),
    KkBinaryDescription(key="backup_active", name="Backup active", value_fn=lambda s: s.mode_value("backup_active")),
    KkBinaryDescription(key="backup_outlet_armed", name="Backup outlet armed",
                        value_fn=lambda s: s.mode_value("backup_outlet_armed")),
    KkBinaryDescription(key="generator_relay", name="Generator relay", value_fn=lambda s: s.gen("relay_closed")),
    KkBinaryDescription(key="picmk_link", name="Power controller link", device_class=BinarySensorDeviceClass.CONNECTIVITY,
                        value_fn=lambda s: s.link_up, needs_live_link=False),
)


class KkBinarySensor(KkEntity, BinarySensorEntity):
    entity_description: KkBinaryDescription

    def __init__(self, coordinator: KkCoordinator, description: KkBinaryDescription) -> None:
        super().__init__(coordinator, description.key)
        self.entity_description = description
        self._needs_live_link = description.needs_live_link

    @property
    def is_on(self) -> bool | None:
        return self.entity_description.value_fn(self.coordinator.kk)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    coordinator: KkCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(KkBinarySensor(coordinator, d) for d in DESCRIPTIONS)
