"""Local-channel client for the KK HMI: wss with mutual TLS, no Home Assistant imports.

Protocol:
  wss://host:port/ws, subprotocol kk.hmi.v1. The device speaks first (`hello`), the client answers
  `auth` (mtls), the device replies `auth_result` and a `snapshot`. The client then `subscribe`s
  and receives `telemetry` (per topic), `event` (not subscription-gated) and standalone `error`
  frames. Trust is a pin, not a chain: the server certificate's SHA-256 over its DER
  SubjectPublicKeyInfo, which is NOT what aiohttp.Fingerprint checks (that one
  hashes the whole certificate), so the pin is verified here after the handshake.
The device closes a connection that sent nothing for 60 s (4408). The keepalive is the
app-level `{"t":"ping"}` this client sends every HEARTBEAT_S whatever it receives: aiohttp's own
heartbeat is reset by every inbound frame, so under 1 Hz telemetry it never fires and is not relied on."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import ssl
import tempfile
from typing import Any, Awaitable, Callable

import aiohttp
from cryptography import x509
from cryptography.hazmat.primitives import serialization

_LOGGER = logging.getLogger(__name__)

SUBPROTOCOL = "kk.hmi.v1"
TOPICS = ("power", "battery", "mode", "cells", "temps", "generator")
RATE_MHZ = 1000                      # one push a second at most per topic; pushes are change-gated
HEARTBEAT_S = 15.0
KEEPALIVE_ID_BASE = 900_000_000      # ping ids; the client's own call ids stay far below
BACKOFF_MAX_S = 60.0

CLOSE_TOO_MANY_CLIENTS = 4290        # the HMI holds 4 local clients; the 5th is closed
CLOSE_IDLE = 4408


class KkError(Exception):
    """Base class; `reason` is a short stable key the config flow maps to a message."""
    reason = "unknown"


class CannotConnect(KkError):
    reason = "cannot_connect"


class PinMismatch(KkError):
    reason = "pin_mismatch"


class AuthFailed(KkError):
    reason = "auth_failed"


class TooManyClients(KkError):
    reason = "too_many_clients"


def spki_sha256(der_cert: bytes) -> bytes:
    spki = x509.load_der_x509_certificate(der_cert).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).digest()


def build_ssl_context(cert_pem: str, key_pem: str) -> ssl.SSLContext:
    """Client certificate loaded, verification off: the pin replaces the chain check. The identity
    lives in the config entry as PEM text; `ssl` can only load files, so the pair goes through a
    private temporary directory that is gone again when this returns. Blocking: call it from an
    executor."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    with tempfile.TemporaryDirectory(prefix="kk-hmi-") as d:      # mkdtemp: mode 0700
        cert, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
        for path, text in ((cert, cert_pem), (key, key_pem)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(text)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx


FrameCb = Callable[[dict], Awaitable[None] | None]
StateCb = Callable[[bool, str | None], Awaitable[None] | None]
FatalCb = Callable[[str], Awaitable[None] | None]


class KkClient:
    """One persistent, self-reconnecting session. `on_frame` gets `hello`, `snapshot`, `telemetry`,
    `event` and `error` frames in arrival order; `on_state(connected, last_error)` every time the
    session comes up or goes down. `on_fatal(reason)` fires once, and the client stops retrying,
    when only a new enrolment can help: access revoked (close 1008) or a changed server key
    (`auth_failed`, `pin_mismatch`)."""

    def __init__(self, host: str, port: int, cert_pem: str, key_pem: str, pin_hex: str,
                 on_frame: FrameCb, on_state: StateCb | None = None, name: str = "homeassistant",
                 topics: tuple[str, ...] = TOPICS, rate_mhz: int = RATE_MHZ,
                 session: aiohttp.ClientSession | None = None, backoff_s: float = 1.0,
                 on_fatal: FatalCb | None = None):
        self.host, self.port = host, int(port)
        self.cert_pem, self.key_pem = cert_pem, key_pem
        self.on_fatal = on_fatal
        self.pin = bytes.fromhex(pin_hex)
        self.on_frame, self.on_state = on_frame, on_state
        self.name, self.topics, self.rate_mhz = name, topics, rate_mhz
        self.backoff_s = backoff_s
        self._session = session
        self._own_session = session is None
        self._task: asyncio.Task | None = None
        self._ctx: ssl.SSLContext | None = None
        self.connected = False
        self.last_error: str | None = None
        self.last_reason: str | None = None     # a KkError.reason, or `idle_timeout`
        self.role: str | None = None
        self.hello: dict | None = None

    # -- lifecycle ------------------------------------------------------------------------------
    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.get_running_loop().create_task(self._run(), name="kk_hmi client")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self._own_session and self._session is not None:
            await self._session.close()
            self._session = None

    async def probe(self, timeout: float = 15.0) -> dict:
        """Connect, authenticate, read the first snapshot and disconnect; returns the `hello`.
        Raises a KkError subclass. For the config flow."""
        got: dict = {}

        async def grab(frame: dict) -> None:
            if frame.get("t") == "hello":
                got["hello"] = frame
            elif frame.get("t") == "snapshot":
                got["snapshot"] = frame

        saved = self.on_frame
        self.on_frame = grab
        try:
            await asyncio.wait_for(self._session_once(subscribe=False, stop_after_snapshot=True), timeout)
        except asyncio.TimeoutError:
            raise CannotConnect("timed out") from None
        finally:
            self.on_frame = saved
            if self._own_session and self._session is not None:
                await self._session.close()
                self._session = None
        return got["hello"]

    # -- the loop -------------------------------------------------------------------------------
    async def _run(self) -> None:
        backoff = self.backoff_s
        while True:
            try:
                await self._session_once()
                backoff = self.backoff_s       # it was up; a clean end retries soon
            except asyncio.CancelledError:
                raise
            except KkError as e:
                self.last_error, self.last_reason = f"{e.reason}: {e}", e.reason
                _LOGGER.warning("KK HMI %s:%s: %s", self.host, self.port, self.last_error)
                if isinstance(e, (AuthFailed, PinMismatch)):
                    await self._set_state(False)
                    if self.on_fatal is not None:
                        r = self.on_fatal(e.reason)
                        if asyncio.iscoroutine(r):
                            await r
                    return                     # only a new enrolment helps: do not hammer the device
            except (aiohttp.ClientError, OSError, ssl.SSLError, asyncio.TimeoutError) as e:
                self.last_error, self.last_reason = f"cannot_connect: {type(e).__name__}: {e}", "cannot_connect"
                _LOGGER.warning("KK HMI %s:%s: %s", self.host, self.port, self.last_error)
            except Exception:                  # noqa: BLE001 (a bad frame must not end the integration)
                self.last_error = "unexpected error"
                _LOGGER.exception("KK HMI session failed")
            await self._set_state(False)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, BACKOFF_MAX_S)

    async def _session_once(self, subscribe: bool = True, stop_after_snapshot: bool = False) -> None:
        if self._ctx is None:
            self._ctx = await asyncio.get_running_loop().run_in_executor(
                None, build_ssl_context, self.cert_pem, self.key_pem)
        if self._session is None:
            self._session = aiohttp.ClientSession()
        try:
            ws = await asyncio.wait_for(self._session.ws_connect(
                f"wss://{self.host}:{self.port}/ws", ssl=self._ctx, protocols=(SUBPROTOCOL,),
                heartbeat=HEARTBEAT_S, max_msg_size=64 * 1024), 15.0)
        except aiohttp.WSServerHandshakeError as e:
            raise CannotConnect(f"upgrade refused: HTTP {e.status}") from None
        except (aiohttp.ClientError, OSError, ssl.SSLError, asyncio.TimeoutError) as e:
            # An unenrolled certificate is refused at the TLS layer, so a dropped or
            # alerted handshake is also what "not on the allow-list" looks like from here.
            raise CannotConnect(f"{type(e).__name__}: {e}") from None
        async with ws:
            ssl_obj = ws.get_extra_info("ssl_object")
            der = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
            if not der or spki_sha256(der) != self.pin:
                got = spki_sha256(der).hex()[:16] if der else "none"
                raise PinMismatch(f"server key {got}... is not the pinned {self.pin.hex()[:16]}...")
            hello = await self._expect(ws, "hello")
            self.hello = hello
            await self._emit(hello)
            await ws.send_json({"t": "auth", "id": 1, "method": "mtls",
                                "client": {"name": self.name, "kind": "homeassistant", "app_version": "1.0.0"}})
            res = await self._expect(ws, "auth_result")
            if not res.get("ok"):
                raise AuthFailed(str((res.get("error") or {}).get("code") or res))
            self.role = res.get("role")
            if subscribe:
                await ws.send_json({"t": "subscribe", "id": 2, "topics": [
                    {"topic": t, "rate_mhz": self.rate_mhz} for t in self.topics]})
            await self._set_state(True)
            ka = asyncio.get_running_loop().create_task(self._keepalive(ws), name="kk_hmi keepalive")
            try:
                await self._read_loop(ws, stop_after_snapshot)
            finally:
                ka.cancel()
            code = ws.close_code
            if code == CLOSE_TOO_MANY_CLIENTS:
                raise TooManyClients("the device already has 4 local clients")
            if code == 1008:
                raise AuthFailed("access revoked")
            if code == CLOSE_IDLE:
                self.last_error, self.last_reason = f"closed {CLOSE_IDLE} idle timeout", "idle_timeout"
                _LOGGER.warning("KK HMI %s:%s: %s", self.host, self.port, self.last_error)
            elif code is not None:
                _LOGGER.info("KK HMI %s:%s: closed by the device (code %s)", self.host, self.port, code)

    async def _keepalive(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        n = 0
        try:
            while not ws.closed:
                await asyncio.sleep(HEARTBEAT_S)
                n += 1
                await ws.send_json({"t": "ping", "id": KEEPALIVE_ID_BASE + n})
        except (aiohttp.ClientError, ConnectionError, RuntimeError):
            pass                             # the read loop sees the close

    async def _read_loop(self, ws: aiohttp.ClientWebSocketResponse, stop_after_snapshot: bool) -> None:
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                try:
                    frame = json.loads(msg.data)
                except ValueError:
                    continue
                if not isinstance(frame, dict):
                    continue
                t = frame.get("t")
                if t == "pong":
                    continue             # keepalive answer, not data
                if t == "sub_result":
                    bad = [a for a in frame.get("applied") or [] if a.get("error")]
                    if bad:
                        _LOGGER.warning("KK HMI refused topics: %s", bad)
                elif t in ("snapshot", "telemetry", "event", "error"):
                    await self._emit(frame)
                    if stop_after_snapshot and t == "snapshot":
                        return
            elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING,
                              aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                break

    async def _expect(self, ws: aiohttp.ClientWebSocketResponse, t: str, timeout: float = 10.0) -> dict:
        """The next frame, which must be `t`. A close first is reported by its code."""
        msg = await asyncio.wait_for(ws.receive(), timeout)
        if msg.type == aiohttp.WSMsgType.TEXT:
            frame = json.loads(msg.data)
            if frame.get("t") == t:
                return frame
            if frame.get("t") == "error":
                raise AuthFailed(str((frame.get("error") or {}).get("code")))
            raise CannotConnect(f"expected {t}, got {frame.get('t')}")
        if ws.close_code == CLOSE_TOO_MANY_CLIENTS:
            raise TooManyClients("the device already has 4 local clients")
        raise CannotConnect(f"connection ended before {t} (close code {ws.close_code})")

    async def _emit(self, frame: dict) -> None:
        r = self.on_frame(frame)
        if asyncio.iscoroutine(r):
            await r

    async def _set_state(self, connected: bool) -> None:
        if connected:
            self.last_error = self.last_reason = None
        if connected == self.connected:
            return
        self.connected = connected
        if self.on_state is not None:
            r = self.on_state(connected, self.last_error)
            if asyncio.iscoroutine(r):
                await r
