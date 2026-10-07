"""Sensors: power flows, per-pack battery and cells, temperatures, generator, mode, alarms."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (SensorDeviceClass, SensorEntity, SensorEntityDescription,
                                             SensorStateClass)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (PERCENTAGE, UnitOfElectricCurrent, UnitOfElectricPotential, UnitOfFrequency,
                                 UnitOfPower, UnitOfTemperature, UnitOfTime)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import KkCoordinator
from .entity import KkEntity
from .model import KkState

MEAS = SensorStateClass.MEASUREMENT


@dataclass(frozen=True, kw_only=True)
class KkSensorDescription(SensorEntityDescription):
    value_fn: Callable[[KkState], Any]
    attrs_fn: Callable[[KkState], dict] | None = None


def _power(key: str, name: str, fn: Callable[[KkState], Any]) -> KkSensorDescription:
    return KkSensorDescription(key=key, name=name, device_class=SensorDeviceClass.POWER,
                               native_unit_of_measurement=UnitOfPower.WATT, state_class=MEAS, value_fn=fn)


def _temp(key: str, name: str, fn: Callable[[KkState], Any]) -> KkSensorDescription:
    return KkSensorDescription(key=key, name=name, device_class=SensorDeviceClass.TEMPERATURE,
                               native_unit_of_measurement=UnitOfTemperature.CELSIUS, state_class=MEAS, value_fn=fn)


STATIC: tuple[KkSensorDescription, ...] = (
    _power("pv_power", "PV power", lambda s: s.pv_power_w),
    _power("grid_import", "Grid import", lambda s: s.power_value("grid_import_w")),
    _power("grid_export", "Grid export", lambda s: s.power_value("grid_export_w")),
    _power("battery_power", "Battery power", lambda s: s.power_value("battery_power_w")),
    _power("house_load", "House load", lambda s: s.power_value("house_load_w")),
    _power("ac_out_power", "AC output power", lambda s: s.ac_out_power_w),
    KkSensorDescription(key="ac_out_voltage", name="AC output voltage", device_class=SensorDeviceClass.VOLTAGE,
                        native_unit_of_measurement=UnitOfElectricPotential.VOLT, state_class=MEAS,
                        value_fn=lambda s: s.ac_out_voltage_v),
    KkSensorDescription(key="ac_out_frequency", name="AC output frequency", device_class=SensorDeviceClass.FREQUENCY,
                        native_unit_of_measurement=UnitOfFrequency.HERTZ, state_class=MEAS,
                        value_fn=lambda s: s.ac_out_frequency_hz),
    _temp("temp_heatsink", "Inverter heatsink temperature", lambda s: s.temp("inverter_heatsink_dc")),
    _temp("temp_enclosure", "Enclosure temperature", lambda s: s.temp("enclosure_internal_dc")),
    _temp("temp_ambient", "Ambient temperature", lambda s: s.temp("ambient_dc")),
    _temp("temp_boost_inductor", "Boost inductor temperature", lambda s: s.temp("boost_inductor_dc")),
    KkSensorDescription(key="generator_state", name="Generator state", value_fn=lambda s: s.gen("state")),
    KkSensorDescription(key="generator_voltage", name="Generator voltage", device_class=SensorDeviceClass.VOLTAGE,
                        native_unit_of_measurement=UnitOfElectricPotential.VOLT, state_class=MEAS,
                        value_fn=lambda s: s.generator_voltage_v),
    KkSensorDescription(key="generator_frequency", name="Generator frequency",
                        device_class=SensorDeviceClass.FREQUENCY, native_unit_of_measurement=UnitOfFrequency.HERTZ,
                        state_class=MEAS, value_fn=lambda s: s.generator_frequency_hz),
    KkSensorDescription(key="generator_runtime", name="Generator runtime", device_class=SensorDeviceClass.DURATION,
                        native_unit_of_measurement=UnitOfTime.SECONDS, state_class=MEAS,
                        value_fn=lambda s: s.gen("runtime_seconds")),
    KkSensorDescription(key="mode", name="Mode", value_fn=lambda s: s.mode_value("mode"),
                        attrs_fn=lambda s: {"who_has_control": s.mode_value("who_has_control")}),
    _power("setpoint", "Setpoint", lambda s: s.mode_value("setpoint_w")),
    KkSensorDescription(key="power_level", name="Power level", value_fn=lambda s: s.mode_value("power_level")),
    KkSensorDescription(key="alarm_count", name="Active alarms", state_class=MEAS,
                        value_fn=lambda s: s.alarm_count, attrs_fn=lambda s: {"alarms": s.alarm_list}),
)


def pack_descriptions(i: int) -> list[KkSensorDescription]:
    n = f"Pack {i}"
    return [
        KkSensorDescription(key=f"pack{i}_soc", name=f"{n} state of charge", device_class=SensorDeviceClass.BATTERY,
                            native_unit_of_measurement=PERCENTAGE, state_class=MEAS, value_fn=lambda s: s.pack_soc(i)),
        KkSensorDescription(key=f"pack{i}_voltage", name=f"{n} voltage", device_class=SensorDeviceClass.VOLTAGE,
                            native_unit_of_measurement=UnitOfElectricPotential.VOLT, state_class=MEAS,
                            value_fn=lambda s: s.pack_voltage(i)),
        KkSensorDescription(key=f"pack{i}_current", name=f"{n} current", device_class=SensorDeviceClass.CURRENT,
                            native_unit_of_measurement=UnitOfElectricCurrent.AMPERE, state_class=MEAS,
                            value_fn=lambda s: s.pack_current(i)),
        _temp(f"pack{i}_temp", f"{n} temperature", lambda s: s.pack_temp(i)),
        KkSensorDescription(key=f"pack{i}_soh", name=f"{n} state of health", native_unit_of_measurement=PERCENTAGE,
                            state_class=MEAS, value_fn=lambda s: s.pack_soh(i)),
        *[KkSensorDescription(key=f"pack{i}_cell_{w}", name=f"{n} cell {w}", device_class=SensorDeviceClass.VOLTAGE,
                              native_unit_of_measurement=UnitOfElectricPotential.MILLIVOLT, state_class=MEAS,
                              value_fn=lambda s, w=w: s.cell_stat(i, w)) for w in ("min", "max", "delta")],
    ]


class KkSensor(KkEntity, SensorEntity):
    entity_description: KkSensorDescription

    def __init__(self, coordinator: KkCoordinator, description: KkSensorDescription) -> None:
        super().__init__(coordinator, description.key)
        self.entity_description = description

    @property
    def native_value(self) -> Any:
        return self.entity_description.value_fn(self.coordinator.kk)

    @property
    def extra_state_attributes(self) -> dict | None:
        fn = self.entity_description.attrs_fn
        return fn(self.coordinator.kk) if fn else None


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    coordinator: KkCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(KkSensor(coordinator, d) for d in STATIC)
    known: set[int] = set()

    def add_new_packs() -> None:
        new = [i for i in coordinator.kk.pack_ids if i not in known]
        if new:
            known.update(new)
            async_add_entities(KkSensor(coordinator, d) for i in new for d in pack_descriptions(i))

    add_new_packs()
    entry.async_on_unload(coordinator.async_add_listener(add_new_packs))
