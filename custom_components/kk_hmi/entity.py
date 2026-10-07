"""Shared base for the KK HMI entities."""
from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import KkCoordinator


class KkEntity(CoordinatorEntity[KkCoordinator]):
    _attr_has_entity_name = True
    #: the PIC link state does not gate this entity (it reports that state itself)
    _needs_live_link = True

    def __init__(self, coordinator: KkCoordinator, key: str) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.device_id}_{key}"

    @property
    def device_info(self) -> DeviceInfo:
        dev = self.coordinator.kk.device
        return DeviceInfo(identifiers={(DOMAIN, self.coordinator.device_id)}, name="KK HMI",
                          manufacturer="KK", model=dev.get("model"), sw_version=dev.get("fw_hmi"),
                          hw_version=dev.get("fw_picmk"))

    @property
    def available(self) -> bool:
        """Unavailable while the WSS is down, and (for telemetry) while the PIC link is down."""
        c = self.coordinator
        return c.connected and (c.kk.live or not self._needs_live_link)
