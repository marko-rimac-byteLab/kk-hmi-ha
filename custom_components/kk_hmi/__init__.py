"""KK HMI: read-only Home Assistant view of the storage HMI's local WebSocket channel.

The integration is a *viewer* (role viewer in the HMI's allow-list): it subscribes to telemetry and
listens to events, and never issues a command. Its credentials (own certificate, key, server pin)
are created by the config flow's secondary-client enrolment and live in the config entry."""
from __future__ import annotations

import asyncio

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed

from .const import DOMAIN
from .coordinator import KkCoordinator

PLATFORMS = [Platform.SENSOR, Platform.BINARY_SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    coordinator = KkCoordinator(hass, entry)
    coordinator.start()                       # connects in the background; entities start unavailable
    try:                                      # a refused identity must surface now, as "reauthenticate"
        await asyncio.wait_for(coordinator.first_attempt.wait(), 10)
    except asyncio.TimeoutError:
        pass
    if coordinator.fatal:
        await coordinator.async_stop()
        raise ConfigEntryAuthFailed(coordinator.last_error or coordinator.fatal)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        coordinator: KkCoordinator = hass.data[DOMAIN].pop(entry.entry_id)
        await coordinator.async_stop()
    return ok
