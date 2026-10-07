"""Enrolment of a new local client on the HMI, self-contained for HACS.

The user types the code `XXXX-XXXX` that an admin's app shows after `open_enrollment_window`. This
module then (1) generates the integration's own EC key and self-signed certificate under the
local rules (validity from exactly the Unix epoch to 2099, because the HMI's local TLS ignores
certificate time), (2) runs protocomm "Security 2" (SRP6a, SHA-512, 3072-bit group, user `kk-enroll`,
the code as password) against the device's transient listener (`http://<host>:8443`, endpoints
`sec2-session` and `enroll-identity`), (3) submits its certificate fingerprint inside
that PAKE-secured channel and (4) reads the server pin (`local_tls_sha256`) from the answer.

Nothing here needs `protobuf`: the handful of messages are encoded by hand (varint and
length-delimited fields only) and the SRP6a client (RFC 5054) follows ESP-IDF's esp_prov
(Apache-2.0), hashing values exactly as they cross the wire. Only `cryptography` and `aiohttp`
(both in Home Assistant core) are used. No homeassistant import, so it is unit-testable on its own.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import os
from dataclasses import dataclass

import aiohttp
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

ENROLL_PORT = 8443
SRP_USERNAME = "kk-enroll"
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"      # no 0/O, 1/I: easy to read aloud
ENROLLED_OK = 1                                         # LocalEnrollState
NOT_BEFORE = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)                     # exactly the epoch: valid at any device clock
NOT_AFTER = dt.datetime(2099, 12, 31, 23, 59, 59, tzinfo=dt.timezone.utc)


# -- errors (`reason` is the config flow's error key) ------------------------------------------------
class EnrollError(Exception):
    reason = "unknown"


class WrongCode(EnrollError):
    reason = "wrong_code"


class WindowClosed(EnrollError):
    """Nothing listens on the enrolment port: no window open, it expired, was used, or the fifth
    wrong code locked it (the listener is torn down in every case)."""
    reason = "window_closed"


class EnrollCannotConnect(EnrollError):
    reason = "cannot_connect"


class EnrollRejected(EnrollError):
    reason = "rejected"


def normalize_code(text: str) -> str:
    """`abcd 2345`, `abcd-2345` or `ABCD2345` -> `ABCD-2345`; anything else comes back upper-cased
    and stripped (the device is the judge, a wrong code just fails the proof)."""
    s = "".join(ch for ch in text.upper() if ch not in " -\t")
    return f"{s[:4]}-{s[4:]}" if len(s) == 8 else s


# -- our own identity ---------------------------------------------------------------------------------
@dataclass(frozen=True)
class Identity:
    cert_pem: str
    key_pem: str
    der: bytes
    fingerprint: bytes          # SHA-256 over the DER SubjectPublicKeyInfo
    label: str = ""


def new_identity(label: str) -> Identity:
    """Blocking (key generation). EC P-256, self-signed, CN = label, validity 1970 to 2099 (
    local auth is time-free and a factory-fresh device's clock is 0)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER).sign(key, hashes.SHA256()))
    spki = key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    return Identity(
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        key_pem=key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()).decode("ascii"),
        der=cert.public_bytes(serialization.Encoding.DER), fingerprint=hashlib.sha256(spki).digest(),
        label=label)


# -- minimal protobuf (proto3: zero and empty fields are omitted, fields in number order) --------------
def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _bytes_field(num: int, v: bytes | str) -> bytes:
    if isinstance(v, str):
        v = v.encode("utf-8")
    return _varint(num << 3 | 2) + _varint(len(v)) + v if v else b""


def _msg_field(num: int, body: bytes) -> bytes:
    """A sub-message is always written once it is set, even when it encodes to nothing."""
    return _varint(num << 3 | 2) + _varint(len(body)) + body


def _int_field(num: int, v: int) -> bytes:
    return _varint(num << 3) + _varint(v) if v else b""


def parse(buf: bytes) -> dict[int, list]:
    """Field number -> values (int for varints, bytes for length-delimited)."""
    out: dict[int, list] = {}
    i, n = 0, len(buf)
    while i < n:
        tag, i = _read_varint(buf, i)
        num, wt = tag >> 3, tag & 7
        if wt == 0:
            v, i = _read_varint(buf, i)
        elif wt == 2:
            ln, i = _read_varint(buf, i)
            if i + ln > n:
                raise ValueError("truncated protobuf field")
            v, i = bytes(buf[i:i + ln]), i + ln
        elif wt == 1:
            v, i = bytes(buf[i:i + 8]), i + 8
        elif wt == 5:
            v, i = bytes(buf[i:i + 4]), i + 4
        else:
            raise ValueError(f"unsupported wire type {wt}")
        out.setdefault(num, []).append(v)
    return out


def _read_varint(buf: bytes, i: int) -> tuple[int, int]:
    shift = v = 0
    while True:
        if i >= len(buf):
            raise ValueError("truncated varint")
        b = buf[i]
        i += 1
        v |= (b & 0x7F) << shift
        if not b & 0x80:
            return v, i
        shift += 7


def _first(d: dict[int, list], num: int, default):
    return d[num][0] if num in d else default


SEC_SCHEME2 = 2
S2_COMMAND0, S2_COMMAND1 = 0, 2


def encode_session_cmd0(username: bytes, client_pubkey: bytes) -> bytes:
    """SessionData{sec_ver=SecScheme2, sec2=Sec2Payload{msg=Command0, sc0={username, pubkey}}}"""
    sc0 = _bytes_field(1, username) + _bytes_field(2, client_pubkey)
    sec2 = _int_field(1, S2_COMMAND0) + _msg_field(20, sc0)
    return _int_field(2, SEC_SCHEME2) + _msg_field(12, sec2)


def encode_session_cmd1(client_proof: bytes) -> bytes:
    sec2 = _int_field(1, S2_COMMAND1) + _msg_field(22, _bytes_field(1, client_proof))
    return _int_field(2, SEC_SCHEME2) + _msg_field(12, sec2)


def _sec2(buf: bytes) -> dict[int, list]:
    top = parse(buf)
    if _first(top, 2, 0) != SEC_SCHEME2 or 12 not in top:
        raise EnrollError("the device did not answer with protocomm Security 2")
    return parse(top[12][0])


def decode_session_resp0(buf: bytes) -> tuple[int, bytes, bytes]:
    """-> (status, device_pubkey, device_salt)"""
    sec2 = _sec2(buf)
    sr0 = parse(_first(sec2, 21, b""))
    return _first(sr0, 1, 0), _first(sr0, 2, b""), _first(sr0, 3, b"")


def decode_session_resp1(buf: bytes) -> tuple[int, bytes, bytes]:
    """-> (status, device_proof, device_nonce)"""
    sec2 = _sec2(buf)
    sr1 = parse(_first(sec2, 23, b""))
    return _first(sr1, 1, 0), _first(sr1, 2, b""), _first(sr1, 3, b"")


def encode_identity_set(fingerprint: bytes, der: bytes, label: str) -> bytes:
    """LocalIdentitySet{client_cert_sha256, client_cert_der, client_label}"""
    return _bytes_field(1, fingerprint) + _bytes_field(2, der) + _bytes_field(3, label)


def encode_identity_result(role: int, pin: bytes, ws_port: int, state: int) -> bytes:
    """LocalIdentityResult (the device's answer; here for the tests' fake device)"""
    return _int_field(1, role) + _bytes_field(2, pin) + _int_field(3, ws_port) + _int_field(4, state)


def decode_identity_result(buf: bytes) -> dict:
    d = parse(buf)
    return {"role": _first(d, 1, 0), "pin": _first(d, 2, b""), "ws_port": _first(d, 3, 0),
            "state": _first(d, 4, 0)}


# -- SRP6a client (SHA-512, N = RFC 3526/5054 3072-bit group, g = 5) -----------------------------------
# Derived from ESP-IDF esp_prov's srp6a.py.
# SPDX-FileCopyrightText: 2022 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
_N_HEX = (
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
    "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
    "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
    "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
    "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
    "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
    "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
    "3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33"
    "a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7"
    "abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864"
    "d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e2"
    "08e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff"
)
_N = int(_N_HEX, 16)
_G = 5
_NLEN = 384


def _sha(*parts: bytes) -> bytes:
    h = hashlib.sha512()
    for p in parts:
        h.update(p)
    return h.digest()


def _i2b(n: int, width: int = 0) -> bytes:
    return n.to_bytes(max(width, (n.bit_length() + 7) // 8), "big")


def srp_x(salt: bytes, user: str, password: str) -> int:
    """x = H(s | H(I ":" P)) over the salt as received and the full 64-byte inner digest."""
    return int.from_bytes(_sha(salt, _sha(f"{user}:{password}".encode())), "big")


class SrpClient:
    """What esp_srp.c computes on the other side: every value is hashed exactly as it crosses the
    wire (A left-padded to 384 bytes, the salt and B as received, x over the full 64-byte H(I:P))."""

    def __init__(self, username: str, password: str, a: int | None = None):
        self.user, self.password = username, password
        self.a = a if a is not None else int.from_bytes(os.urandom(32), "big") | (1 << 255)
        self.A = pow(_G, self.a, _N)
        self.bytes_A = _i2b(self.A, _NLEN)
        self._h_amk = b""
        self.key = b""

    def process_challenge(self, salt: bytes, bytes_b: bytes) -> bytes:
        """-> the client proof M. Raises EnrollError on a degenerate B or u."""
        B = int.from_bytes(bytes_b, "big")
        if B % _N == 0:
            raise EnrollError("SRP6a safety check failed (B)")
        k = int.from_bytes(_sha(_i2b(_N, _NLEN), _i2b(_G, _NLEN)), "big")
        u = int.from_bytes(_sha(_i2b(self.A, _NLEN), _i2b(B, _NLEN)), "big")
        if u == 0:
            raise EnrollError("SRP6a safety check failed (u)")
        x = srp_x(salt, self.user, self.password)
        v = pow(_G, x, _N)
        S = pow(B - k * v, self.a + u * x, _N)
        self.key = _sha(_i2b(S))
        hng = bytes(p ^ q for p, q in zip(_sha(_i2b(_N)), _sha(_i2b(_G, _NLEN))))
        m = _sha(hng, _sha(self.user.encode()), salt, self.bytes_A, bytes_b, self.key)
        self._h_amk = _sha(self.bytes_A, m, self.key)
        return m

    def verify_device(self, device_proof: bytes) -> bool:
        return bool(self._h_amk) and device_proof == self._h_amk


# -- the session: SRP6a, then AES-256-GCM with a counter nonce ------------------------------------------
class Sec2Session:
    def __init__(self, code: str):
        self.srp = SrpClient(SRP_USERNAME, code)
        self._aes: AESGCM | None = None
        self._nonce = bytearray()

    def request0(self) -> bytes:
        return encode_session_cmd0(SRP_USERNAME.encode(), self.srp.bytes_A)

    def request1(self, resp0: bytes) -> bytes:
        status, pub, salt = decode_session_resp0(resp0)
        if status != 0 or not pub or not salt:
            raise EnrollError(f"the device refused the SRP6a start (status {status})")
        return encode_session_cmd1(self.srp.process_challenge(salt, pub))

    def finish(self, resp1: bytes) -> None:
        status, proof, nonce = decode_session_resp1(resp1)
        if status != 0 or not self.srp.verify_device(proof):
            raise WrongCode("the device proof did not verify")
        if len(nonce) != 12:
            raise EnrollError("the device sent no nonce")
        self._aes, self._nonce = AESGCM(self.srp.key[:32]), bytearray(nonce)

    def _bump(self) -> None:
        ctr = int.from_bytes(self._nonce[8:], "big") + 1
        if ctr > 0xFFFFFFFF:
            raise EnrollError("nonce counter overflow")
        self._nonce[8:] = ctr.to_bytes(4, "big")

    def encrypt(self, data: bytes) -> bytes:
        out = self._aes.encrypt(bytes(self._nonce), data, None)
        self._bump()
        return out

    def decrypt(self, data: bytes) -> bytes:
        out = self._aes.decrypt(bytes(self._nonce), data, None)
        self._bump()
        return out


# -- the transport (protocomm_httpd: POST /<endpoint>, plain HTTP; SRP is the security) -------------------
@dataclass(frozen=True)
class Enrolled:
    pin_hex: str                # SPKI SHA-256 of the HMI's wss server certificate: pin it
    role: str
    ws_port: int


async def enroll(session: aiohttp.ClientSession, host: str, code: str, identity: Identity,
                 port: int = ENROLL_PORT, timeout: float = 20.0) -> Enrolled:
    """Run the whole enrolment exchange. Raises an EnrollError subclass; never returns a failed enrolment."""
    loop = asyncio.get_running_loop()
    sec = Sec2Session(code)
    url = f"http://{host}:{port}/"
    to = aiohttp.ClientTimeout(total=timeout)

    async def post(endpoint: str, body: bytes, step: int) -> bytes:
        try:
            async with session.post(url + endpoint, data=body, timeout=to,
                                    headers={"Content-Type": "application/octet-stream"}) as r:
                data = await r.read()
                if r.status != 200:
                    if step == 1:
                        raise WrongCode(f"{endpoint}: HTTP {r.status}")
                    if step == 0:
                        raise WindowClosed(f"{endpoint}: HTTP {r.status}")
                    raise EnrollError(f"{endpoint}: HTTP {r.status}")
                return data
        except EnrollError:
            raise
        except aiohttp.ClientConnectorError as e:
            if isinstance(e.os_error, ConnectionRefusedError):
                raise WindowClosed("nothing listens on the enrolment port") from None
            raise EnrollCannotConnect(f"{type(e).__name__}: {e}") from None
        except (aiohttp.ServerDisconnectedError, aiohttp.ClientPayloadError, ConnectionResetError):
            if step == 1:
                raise WrongCode("the device dropped the connection at the proof") from None
            raise WindowClosed("the device closed the enrolment connection") from None
        except (aiohttp.ClientError, OSError, asyncio.TimeoutError) as e:
            raise EnrollCannotConnect(f"{type(e).__name__}: {e}") from None

    req0 = await loop.run_in_executor(None, sec.request0)
    resp0 = await post("sec2-session", req0, 0)
    try:
        req1 = await loop.run_in_executor(None, sec.request1, resp0)
    except ValueError as e:
        raise EnrollError(f"malformed device answer: {e}") from None
    resp1 = await post("sec2-session", req1, 1)
    try:
        sec.finish(resp1)
        sealed = sec.encrypt(encode_identity_set(identity.fingerprint, identity.der, identity.label))
        resp = await post("enroll-identity", sealed, 2)
        res = decode_identity_result(sec.decrypt(resp))
    except EnrollError:
        raise
    except Exception as e:                       # noqa: BLE001 (bad tag, truncated proto: a bad device answer)
        raise EnrollError(f"malformed device answer: {type(e).__name__}: {e}") from None
    if res["state"] != ENROLLED_OK:
        raise EnrollRejected("the HMI rejected this client certificate")
    if len(res["pin"]) != 32:
        raise EnrollError("the HMI returned no server fingerprint")
    return Enrolled(pin_hex=res["pin"].hex(), role="admin" if res["role"] == 1 else "viewer",
                    ws_port=res["ws_port"] or 443)

