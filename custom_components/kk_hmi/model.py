"""The HMI's state as Home Assistant sees it: frames in, plain values out. No HA imports.

Frames are the local channel's message bodies: `snapshot` replaces everything, `telemetry` replaces one topic
(never with a lower `state_rev`), `event` updates the alarm set and link. Units are
converted here once (permille -> %, mV -> V, dC -> degC, mHz -> Hz); `None` means "not reported
yet", which the entities show as unknown rather than 0."""
from __future__ import annotations

from typing import Any

MODES = ("off", "zero_feed_in", "fixed_power", "backup_only", "grid_charge")
GENERATOR_STATES = ("idle", "starting", "running", "stopping", "fault")


def _div(v: Any, d: float, nd: int | None = None) -> float | None:
    if not isinstance(v, (int, float)) or isinstance(v, bool):
        return None
    r = v / d
    return round(r, nd) if nd is not None else r


class KkState:
    def __init__(self) -> None:
        self.device: dict = {}              # `hello.device`: id, model, fw_hmi, fw_picmk, ...
        self.config: dict = {}
        self.link: dict = {}                # {"picmk": "up"|"degraded"|"down", "stale_ms": n}
        self.power: dict | None = None
        self.battery: dict | None = None
        self.mode: dict | None = None
        self.temps: dict | None = None
        self.generator: dict | None = None
        self.cells: dict[int, dict] = {}    # pack_id -> {"cell_mv": [...]}
        self.alarms: dict[int, dict] = {}   # instance_id -> alarm_raised data
        self.state_rev = -1
        self.last_event: dict | None = None

    # -- frames ---------------------------------------------------------------------------------
    def apply(self, frame: dict) -> set[str]:
        """Fold one frame in; returns what changed (topic / 'link' / 'alarms' / 'config'), empty
        for a frame that changed nothing (an old `state_rev`, an unknown frame)."""
        t = frame.get("t")
        if t == "hello":
            self.device = dict(frame.get("device") or {})
            return {"device"}
        if t == "snapshot":
            return self._snapshot(frame)
        if t == "telemetry":
            return self._telemetry(frame)
        if t == "event":
            return self._event(frame)
        return set()

    def _snapshot(self, f: dict) -> set[str]:
        self.state_rev = f.get("state_rev", self.state_rev)
        self.config = dict(f.get("config") or {})
        self.link = dict(f.get("link") or {})
        for k in ("power", "battery", "mode", "temps", "generator"):
            setattr(self, k, f.get(k))
        self.cells = {c["pack_id"]: c for c in f.get("cells") or [] if isinstance(c, dict) and "pack_id" in c}
        self.alarms = {a["instance_id"]: a for a in f.get("alarms") or [] if "instance_id" in a}
        return {"config", "link", "alarms", "power", "battery", "mode", "temps", "generator", "cells"}

    def _telemetry(self, f: dict) -> set[str]:
        rev = f.get("state_rev")
        if isinstance(rev, int):
            if rev < self.state_rev:        # a client MUST NOT render a lower state_rev over a higher
                return set()
            self.state_rev = rev
        topic, data = f.get("topic"), f.get("data") or {}
        if topic in ("power", "battery", "mode", "temps", "generator"):
            setattr(self, topic, data)
            return {topic}
        if topic == "cells" and "pack_id" in data:
            self.cells[data["pack_id"]] = data
            return {"cells"}
        return set()

    def _event(self, f: dict) -> set[str]:
        self.last_event = f
        name, data = f.get("name"), f.get("data") or {}
        if name == "alarm_raised" and "instance_id" in data:
            self.alarms[data["instance_id"]] = data
            return {"alarms"}
        if name == "alarm_cleared":
            return {"alarms"} if self.alarms.pop(data.get("instance_id"), None) is not None else set()
        if name == "link_status":
            self.link = {"picmk": data.get("picmk"), "stale_ms": data.get("stale_ms", 0)}
            return {"link"}
        return {"event"}

    # -- link / availability --------------------------------------------------------------------
    @property
    def link_status(self) -> str | None:
        return self.link.get("picmk")

    @property
    def link_up(self) -> bool | None:
        s = self.link_status
        return None if s is None else s == "up"

    @property
    def live(self) -> bool:
        """Telemetry is trustworthy: the PIC link is not down (degraded still reports old values)."""
        return self.link_status != "down"

    # -- power ----------------------------------------------------------------------------------
    @property
    def pv_power_w(self) -> int | None:
        if self.power is None:
            return None
        return sum(int(c.get("power_w", 0)) for c in self.power.get("pv") or [])

    def power_value(self, key: str) -> Any:
        return None if self.power is None else self.power.get(key)

    @property
    def ac_out_power_w(self) -> int | None:
        return None if self.power is None else (self.power.get("ac_out") or {}).get("power_w")

    @property
    def ac_out_voltage_v(self) -> float | None:
        return None if self.power is None else _div((self.power.get("ac_out") or {}).get("voltage_mv"), 1000, 1)

    @property
    def ac_out_frequency_hz(self) -> float | None:
        return None if self.power is None else _div((self.power.get("ac_out") or {}).get("frequency_mhz"), 1000, 3)

    # -- batteries ------------------------------------------------------------------------------
    @property
    def pack_ids(self) -> list[int]:
        ids = {p["pack_id"] for p in (self.battery or {}).get("packs") or [] if "pack_id" in p}
        return sorted(ids | set(self.cells))

    def pack(self, pack_id: int) -> dict | None:
        for p in (self.battery or {}).get("packs") or []:
            if p.get("pack_id") == pack_id:
                return p
        return None

    def pack_soc(self, i: int) -> float | None:
        p = self.pack(i)
        return None if p is None else _div(p.get("soc_permille"), 10, 1)

    def pack_voltage(self, i: int) -> float | None:
        p = self.pack(i)
        return None if p is None else _div(p.get("voltage_mv"), 1000, 2)

    def pack_current(self, i: int) -> float | None:
        p = self.pack(i)
        return None if p is None else _div(p.get("current_ma"), 1000, 2)

    def pack_temp(self, i: int) -> float | None:
        p = self.pack(i)
        return None if p is None else _div(p.get("temp_avg_dc"), 10, 1)

    def pack_soh(self, i: int) -> float | None:
        p = self.pack(i)
        return None if p is None else _div(p.get("soh_permille"), 10, 1)

    def cell_stat(self, i: int, which: str) -> int | None:
        mv = [v for v in (self.cells.get(i) or {}).get("cell_mv") or [] if isinstance(v, int)]
        if not mv:
            return None
        return {"min": min(mv), "max": max(mv), "delta": max(mv) - min(mv)}[which]

    # -- temperatures ---------------------------------------------------------------------------
    def temp(self, key: str) -> float | None:
        return None if self.temps is None else _div(self.temps.get(key), 10, 1)

    # -- generator ------------------------------------------------------------------------------
    def gen(self, key: str) -> Any:
        return None if self.generator is None else self.generator.get(key)

    @property
    def generator_voltage_v(self) -> float | None:
        return _div(self.gen("voltage_mv"), 1000, 1)

    @property
    def generator_frequency_hz(self) -> float | None:
        return _div(self.gen("frequency_mhz"), 1000, 3)

    # -- mode -----------------------------------------------------------------------------------
    def mode_value(self, key: str) -> Any:
        return None if self.mode is None else self.mode.get(key)

    @property
    def alarm_count(self) -> int:
        return len(self.alarms)

    @property
    def alarm_list(self) -> list[dict]:
        return [self.alarms[k] for k in sorted(self.alarms)]
