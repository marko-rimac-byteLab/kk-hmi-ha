"""Push coordinator: the client's frames fold into a KkState and update the entities at once."""
from __future__ import annotations

import asyncio
import logging

from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .client import KkClient
from .const import CONF_CERT, CONF_HOST, CONF_KEY, CONF_PIN, CONF_PORT, DOMAIN, EVENT
from .model import KkState

_LOGGER = logging.getLogger(__name__)


class KkCoordinator(DataUpdateCoordinator[KkState]):
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(hass, _LOGGER, name=DOMAIN, config_entry=entry)   # push: no update_interval
        self.kk = KkState()
        self.connected = False
        self.last_error: str | None = None
        self.device_id: str = entry.unique_id or entry.entry_id
        d = entry.data
        self.client = KkClient(d[CONF_HOST], d[CONF_PORT], d[CONF_CERT], d[CONF_KEY], d[CONF_PIN],
                               self._on_frame, self._on_state, session=async_get_clientsession(hass),
                               on_fatal=self._on_fatal)
        self.fatal: str | None = None            # auth_failed / pin_mismatch: only a re-enrolment helps
        self.first_attempt = asyncio.Event()     # set once the first connect succeeded or failed
        self.async_set_updated_data(self.kk)

    def start(self) -> None:
        self.client.start()

    async def async_stop(self) -> None:
        ir.async_delete_issue(self.hass, DOMAIN, self._issue_id)
        await self.client.stop()

    @property
    def _issue_id(self) -> str:
        return f"too_many_clients_{self.config_entry.entry_id}"

    async def _on_fatal(self, reason: str) -> None:
        """Revoked (1008) or the server key changed: say so in the UI ("Reauthenticate") instead of
        retrying forever; the reauth flow enrols again with a fresh code."""
        self.fatal = reason
        self.first_attempt.set()
        if self.config_entry.state is ConfigEntryState.LOADED:   # during setup, setup raises instead
            self.config_entry.async_start_reauth(self.hass)

    async def _on_state(self, connected: bool, err: str | None) -> None:
        self.connected, self.last_error = connected, err
        if connected or err:
            self.first_attempt.set()
        reason = self.client.last_reason
        if connected:
            ir.async_delete_issue(self.hass, DOMAIN, self._issue_id)
        elif reason == "too_many_clients":
            # The device holds at most 4 local clients. Not silent: a Repairs entry stays until we get in.
            ir.async_create_issue(
                self.hass, DOMAIN, self._issue_id, is_fixable=False, severity=ir.IssueSeverity.ERROR,
                translation_key="too_many_clients",
                translation_placeholders={"host": self.client.host})
        self.async_set_updated_data(self.kk)

    async def _on_frame(self, frame: dict) -> None:
        changed = self.kk.apply(frame)
        if frame.get("t") == "event":
            # Every HMI event is also a bus event, so automations can trigger on alarms and relays.
            self.hass.bus.async_fire(EVENT, {"device_id": self.device_id, "name": frame.get("name"),
                                             "data": frame.get("data") or {}, "ts": frame.get("ts")})
        if changed:
            self.async_set_updated_data(self.kk)
