"""Config flow: the production way in, the enrolment of a new local client with a one-time code.

1. The HMI is found by zeroconf (`_kkstorage._tcp`, unique id = TXT `id`) or its host is typed.
2. In the mobile app an admin taps "Add local client" (role viewer, label `home-assistant`); the app
   shows a code `XXXX-XXXX` for two minutes.
3. The user types the code here. The integration makes its own key and certificate, enrols against
   `<host>:8443` (enroll.py), pins the server key the HMI returns, proves the result by really
   connecting (mTLS, auth) and creates the entry. Certificate, key and pin live in the entry.
Reauthentication (`async_step_reauth`) is the same code form: the device revoked this client (close
1008) or its server key changed (factory reset), so a fresh code re-enrols and the entry is updated."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.service_info.zeroconf import ZeroconfServiceInfo

from .client import KkClient, KkError
from .const import (CLIENT_LABEL, CONF_CERT, CONF_DEVICE_ID, CONF_HOST, CONF_KEY, CONF_PIN, CONF_PORT,
                    DEFAULT_PORT, DOMAIN)
from .enroll import EnrollError, enroll, new_identity, normalize_code

_LOGGER = logging.getLogger(__name__)
CONF_CODE = "code"


class KkConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._host: str = ""
        self._port: int = DEFAULT_PORT
        self._device_id: str | None = None

    # -- the three ways in --------------------------------------------------------------------
    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            self._host, self._port = user_input[CONF_HOST].strip(), int(user_input[CONF_PORT])
            return await self.async_step_enroll()
        return self.async_show_form(step_id="user", data_schema=vol.Schema({
            vol.Required(CONF_HOST): str, vol.Required(CONF_PORT, default=DEFAULT_PORT): int}))

    async def async_step_zeroconf(self, discovery_info: ZeroconfServiceInfo) -> ConfigFlowResult:
        self._host, self._port = discovery_info.host, discovery_info.port or DEFAULT_PORT
        self._device_id = discovery_info.properties.get("id")
        if self._device_id:
            await self.async_set_unique_id(self._device_id)
            self._abort_if_unique_id_configured(updates={CONF_HOST: self._host, CONF_PORT: self._port})
        self.context["title_placeholders"] = {"name": self._device_id or self._host}
        return await self.async_step_enroll()

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> ConfigFlowResult:
        self._host, self._port = entry_data[CONF_HOST], entry_data[CONF_PORT]
        self._device_id = entry_data.get(CONF_DEVICE_ID)
        return await self.async_step_reauth_confirm()

    # -- the code form ------------------------------------------------------------------------
    async def _enrol(self, code_text: str) -> tuple[dict | None, str | None]:
        """(entry data, error key). Enrol, then prove it by connecting for real."""
        session = async_get_clientsession(self.hass)
        ident = await self.hass.async_add_executor_job(new_identity, CLIENT_LABEL)
        try:
            got = await enroll(session, self._host, normalize_code(code_text), ident)
        except EnrollError as e:
            _LOGGER.warning("KK HMI enrolment at %s failed: %s: %s", self._host, e.reason, e)
            return None, e.reason
        except Exception:                              # noqa: BLE001
            _LOGGER.exception("KK HMI enrolment crashed")
            return None, "unknown"
        client = KkClient(self._host, self._port, ident.cert_pem, ident.key_pem, got.pin_hex,
                          lambda f: None, session=session)
        try:
            hello = await client.probe()
        except KkError as e:
            return None, e.reason
        except Exception:                              # noqa: BLE001
            return None, "unknown"
        dev_id = (hello.get("device") or {}).get("id") or self._device_id or f"{self._host}:{self._port}"
        return {CONF_HOST: self._host, CONF_PORT: self._port, CONF_CERT: ident.cert_pem,
                CONF_KEY: ident.key_pem, CONF_PIN: got.pin_hex, CONF_DEVICE_ID: dev_id}, None

    def _code_schema(self) -> vol.Schema:
        return vol.Schema({vol.Required(CONF_CODE): str})

    async def async_step_enroll(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            data, err = await self._enrol(user_input[CONF_CODE])
            if data:
                await self.async_set_unique_id(data[CONF_DEVICE_ID])
                self._abort_if_unique_id_configured(updates=data)
                return self.async_create_entry(title=f"KK HMI {data[CONF_DEVICE_ID]}", data=data)
            errors["base"] = err or "unknown"
        return self.async_show_form(
            step_id="enroll", data_schema=self._code_schema(), errors=errors,
            description_placeholders={"host": self._host})

    async def async_step_reauth_confirm(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        entry = self._get_reauth_entry()
        if user_input is not None:
            data, err = await self._enrol(user_input[CONF_CODE])
            if data and entry.unique_id and data[CONF_DEVICE_ID] != entry.unique_id:
                data, err = None, "wrong_device"
            if data:
                return self.async_update_reload_and_abort(entry, data_updates=data)
            errors["base"] = err or "unknown"
        return self.async_show_form(
            step_id="reauth_confirm", data_schema=self._code_schema(), errors=errors,
            description_placeholders={"host": self._host})
