#!/usr/bin/env python3
"""Generate golden vectors for the .NET port (PORT_PLAN.md checklist items 3 & 4).

Run from anywhere; it imports the reference implementation from
tg-ws-proxy-main_py/proxy and writes JSON files into this directory.

Outputs
  aes_ctr.json            - AES-128/192/256 CTR keystreams, streaming splits
  obfs2_handshake.json    - _try_handshake parse results + client init bytes
  relay_init_fixed.json   - _generate_relay_init with a fixed RNG stream
  crypto_ctx_streams.json - _build_crypto_ctx four-stream outputs
  x25519.json             - X25519 keygen/exchange determinism
  fake_tls_verify.json    - verify_client_hello inputs/outputs
  fake_tls_parse.json     - parse_client_hello inputs/outputs
  fake_tls_serverhello.json - build_server_hello with fixed random sources
  fake_tls_wrap.json      - wrap_tls_record chunking
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import sys
import time
import random as _random_module
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2] / "tg-ws-proxy-main_py"
sys.path.insert(0, str(REPO))

from proxy._aes import Cipher, algorithms, modes                      # noqa: E402
from proxy.utils import (                                             # noqa: E402
    HANDSHAKE_LEN, SKIP_LEN, PREKEY_LEN, IV_LEN, PROTO_TAG_POS,
    PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE,
)
from proxy.tg_ws_proxy import (                                       # noqa: E402
    _try_handshake, _generate_relay_init, _build_crypto_ctx,
)
from proxy import fake_tls                                            # noqa: E402


def hx(b: bytes) -> str:
    return b.hex()


def unhex(s: str) -> bytes:
    return bytes.fromhex(s)


def write(name: str, obj) -> None:
    p = HERE / name
    p.write_text(json.dumps(obj, indent=2, sort_keys=False) + "\n")
    print(f"wrote {p.name} ({p.stat().st_size} bytes)")


class ByteSource:
    """Deterministic xorshift64* byte stream standing in for os.urandom."""

    def __init__(self, seed: int):
        self.state = seed & ((1 << 64) - 1) or 1

    def next(self) -> int:
        s = self.state
        s ^= (s >> 12) & 0xFFFFFFFFFFFFFFFF
        s = (s ^ (s << 25)) & 0xFFFFFFFFFFFFFFFF
        s ^= (s >> 27) & 0xFFFFFFFFFFFFFFFF
        self.state = s
        return (s * 2685821657736338717) & 0xFFFFFFFFFFFFFFFF

    def randbytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            v = self.next()
            out.extend(v.to_bytes(8, "big"))
        return bytes(out[:n])


def make_client_handshake(secret: bytes, prekey: bytes, iv: bytes,
                          proto_tag: bytes, dc_idx: int, fill: ByteSource) -> bytes:
    rnd = bytearray(fill.randbytes(HANDSHAKE_LEN))
    while rnd[0] == 0xEF:
        rnd[0] = fill.randbytes(1)[0]
    rnd[SKIP_LEN:SKIP_LEN + PREKEY_LEN] = prekey
    rnd[SKIP_LEN + PREKEY_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN] = iv
    enc_key = hashlib.sha256(prekey + secret).digest()
    keystream = Cipher(algorithms.AES(enc_key),
                       modes.CTR(iv)).encryptor().update(bytes(HANDSHAKE_LEN))
    tail = proto_tag + struct.pack("<h", dc_idx) + fill.randbytes(2)
    hs = bytearray(rnd)
    for i, b in enumerate(tail):
        hs[PROTO_TAG_POS + i] = b ^ keystream[PROTO_TAG_POS + i]
    return bytes(hs)


# ---------------------------------------------------------------------------
# 1. AES-CTR vectors
# ---------------------------------------------------------------------------
def gen_aes():
    cases = []
    specs = [
        ("CTRAES-128", "2b7e151628aed2a6abf7158809cf4f3c",
         "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        ("CTRAES-192", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c7b7b",
         "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        ("CTRAES-256", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
         "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
    ]
    pt_src = ByteSource(0xABCDEF0123456789)
    plaintexts = [
        pt_src.randbytes(64),
        pt_src.randbytes(1),
        pt_src.randbytes(15),
        pt_src.randbytes(17),
        pt_src.randbytes(333),
        b"",
    ]
    for name, key, iv in specs:
        key_b, iv_b = unhex(key), unhex(iv)
        streams = []
        for pt in plaintexts:
            ct = Cipher(algorithms.AES(key_b), modes.CTR(iv_b)).encryptor().update(pt)
            enc = Cipher(algorithms.AES(key_b), modes.CTR(iv_b)).encryptor()
            acc = bytearray()
            for i in range(0, len(pt), 7):
                acc.extend(enc.update(pt[i:i + 7]))
            streams.append({
                "input": hx(pt),
                "single_update": hx(ct),
                "chunked_update_7": hx(bytes(acc)),
            })
        carry_iv = bytes(15) + b"\xff"
        ct_carry = Cipher(algorithms.AES(key_b),
                          modes.CTR(carry_iv)).encryptor().update(bytes(48))
        cases.append({"name": name, "key": key, "iv": iv, "streams": streams,
                      "carry_iv": hx(carry_iv), "carry_ct": hx(ct_carry)})
    write("aes_ctr.json", cases)


# ---------------------------------------------------------------------------
# 2. obfuscated2 handshake parsing
# ---------------------------------------------------------------------------
def gen_handshakes():
    secret = unhex("00112233445566778899aabbccddeeff")
    fill = ByteSource(0x0BADC0DE)
    out = {"secret": hx(secret), "cases": []}
    for proto, dc in [(PROTO_TAG_ABRIDGED, 2), (PROTO_TAG_INTERMEDIATE, 4),
                      (PROTO_TAG_SECURE, -5), (PROTO_TAG_SECURE, 10001),
                      (PROTO_TAG_ABRIDGED, -1)]:
        prekey = fill.randbytes(PREKEY_LEN)
        iv = fill.randbytes(IV_LEN)
        hs = make_client_handshake(secret, prekey, iv, proto, dc, fill)
        res = _try_handshake(hs, secret)
        assert res is not None
        bad = _try_handshake(hs, unhex("ffffffffffffffffffffffffffffffff"))
        out["cases"].append({
            "handshake": hx(hs),
            "dc_id": res[0], "is_media": res[1],
            "proto_tag": hx(res[2]),
            "dec_prekey_and_iv": hx(res[3]),
            "wrong_secret_returns_none": bad is None,
        })
    out["cases"].append({"handshake": hx(unhex(out["cases"][0]["handshake"])[:63]),
                         "expect_none": True})
    write("obfs2_handshake.json", out)


# ---------------------------------------------------------------------------
# 3. relay init generation with fixed RNG (os.urandom monkeypatched)
# ---------------------------------------------------------------------------
def gen_relay_init():
    urandom = os.urandom
    src = ByteSource(0xFEEDFACE)
    os.urandom = lambda n, _s=src: _s.randbytes(n)
    try:
        cases = []
        for proto, dc in [(PROTO_TAG_ABRIDGED, 2), (PROTO_TAG_INTERMEDIATE, 4),
                          (PROTO_TAG_SECURE, -5), (PROTO_TAG_SECURE, 10002)]:
            ri = _generate_relay_init(proto, dc)
            cases.append({"proto_tag": hx(proto), "dc_idx": dc, "relay_init": hx(ri)})
    finally:
        os.urandom = urandom
    write("relay_init_fixed.json",
          {"note": "os.urandom replaced by xorshift64* stream seeded 0xFEEDFACE; "
                   "rejection loop consumes 64-byte draws until first byte != 0xEF, "
                   "starts not in RESERVED_STARTS and rnd[4:8] != 0000",
           "cases": cases})
    return cases


# ---------------------------------------------------------------------------
# 4. CryptoCtx four streams
# ---------------------------------------------------------------------------
def gen_crypto_ctx(relay_cases):
    secret = unhex("00112233445566778899aabbccddeeff")
    fill = ByteSource(0x5EEDBEEF)
    out = {"secret": hx(secret), "cases": []}
    for case in relay_cases:
        relay_init = unhex(case["relay_init"])
        proto_tag = unhex(case["proto_tag"])
        dc_idx = case["dc_idx"]
        prekey = fill.randbytes(PREKEY_LEN)
        iv = fill.randbytes(IV_LEN)
        handshake = make_client_handshake(secret, prekey, iv, proto_tag, dc_idx, fill)
        res = _try_handshake(handshake, secret)
        assert res is not None
        ctx = _build_crypto_ctx(res[3], secret, relay_init)
        blobs = [fill.randbytes(300), fill.randbytes(1)]
        out["cases"].append({
            "handshake": hx(handshake),
            "relay_init": hx(relay_init),
            "clt_dec": [hx(ctx.clt_dec.update(b)) for b in blobs],
            "clt_enc": [hx(ctx.clt_enc.update(b)) for b in blobs],
            "tg_enc": [hx(ctx.tg_enc.update(b)) for b in blobs],
            "tg_dec": [hx(ctx.tg_dec.update(b)) for b in blobs],
        })
    write("crypto_ctx_streams.json", out)


# ---------------------------------------------------------------------------
# 5. X25519 vectors
# ---------------------------------------------------------------------------
def gen_x25519():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    vecs = []
    alice_priv = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob_priv = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e01f")
    ap = X25519PrivateKey.from_private_bytes(alice_priv)
    bp = X25519PrivateKey.from_private_bytes(bob_priv)
    vecs.append({
        "name": "rfc7748-style-pair",
        "private_a": hx(alice_priv), "public_a": hx(ap.public_key().public_bytes_raw()),
        "private_b": hx(bob_priv), "public_b": hx(bp.public_key().public_bytes_raw()),
        "shared_ab": hx(ap.exchange(bp.public_key())),
        "shared_ba": hx(bp.exchange(ap.public_key())),
    })
    src = ByteSource(0x0C0FFEE00DAD5EED)
    for i in range(4):
        priv = src.randbytes(32)
        k = X25519PrivateKey.from_private_bytes(priv)
        other_priv = src.randbytes(32)
        other = X25519PrivateKey.from_private_bytes(other_priv)
        vecs.append({
            "name": f"random-{i}",
            "private_a": hx(priv), "public_a": hx(k.public_key().public_bytes_raw()),
            "private_b": hx(other_priv), "public_b": hx(other.public_key().public_bytes_raw()),
            "shared_ab": hx(k.exchange(other.public_key())),
        })
    write("x25519.json",
          {"note": "cryptography X25519 raw little-endian scalars; exchange clamps per RFC 7748",
           "vectors": vecs})


# ---------------------------------------------------------------------------
# 6. FakeTLS verify_client_hello
# ---------------------------------------------------------------------------
def build_fake_client_hello(secret: bytes, ts: int, session_id: bytes,
                            suites=(0x1301, 0x1303), key_shares=((0x001D, 32),),
                            supported_versions_ext=True, fill=None):
    """ClientHello whose random field carries the tag HMAC like real clients do."""
    fill = fill or ByteSource(0x01234567)
    legacy_version = b"\x03\x03"
    suites_b = struct.pack(">H", len(suites) * 2) + b"".join(
        struct.pack(">H", s) for s in suites)
    comps = b"\x01\x00"
    ext = b""
    if supported_versions_ext:
        ext += struct.pack(">HHH", 0x002B, 2, 0x0304)
    if key_shares:
        inner = b""
        for group, klen in key_shares:
            inner += struct.pack(">HH", group, klen) + fill.randbytes(klen)
        ext += struct.pack(">HH", 0x0033, len(inner) + 2) + struct.pack(">H", len(inner)) + inner
    extensions = struct.pack(">H", len(ext)) + ext
    hs_body = (legacy_version + bytes(32) + bytes([len(session_id)])
               + session_id + suites_b + comps + extensions)
    message = b"\x01" + struct.pack(">I", len(hs_body))[1:] + hs_body
    record = b"\x16\x03\x01" + struct.pack(">H", len(message)) + message
    zeroed = bytearray(record)
    zeroed[11:43] = bytes(32)
    expected = hmac.new(secret, bytes(zeroed), hashlib.sha256).digest()
    ts_bytes = struct.pack("<I", ts & 0xFFFFFFFF)
    new_random = expected[:28] + bytes(expected[28 + i] ^ ts_bytes[i] for i in range(4))
    stamped = bytearray(record)
    stamped[11:43] = new_random
    return bytes(stamped)


def gen_fake_tls_verify():
    secret = unhex("000102030405060708090a0b0c0d0e0f")
    now = int(time.time())
    sid = unhex("aa" * 32)
    cases = []
    hello = build_fake_client_hello(secret, now, sid)
    res = fake_tls.verify_client_hello(hello, secret)
    assert res is not None
    cases.append({"client_hello": hx(hello), "valid": True,
                  "client_random": hx(res[0]), "session_id": hx(res[1]),
                  "timestamp": res[2]})
    old = build_fake_client_hello(secret, now - 1000, sid)
    cases.append({"client_hello": hx(old), "expect_none": True})
    other = build_fake_client_hello(unhex("ff" * 16), now, sid)
    cases.append({"client_hello": hx(other), "expect_none": True})
    cases.append({"client_hello": hx(hello[:42]), "expect_none": True})
    sid_empty = build_fake_client_hello(secret, now, b"")
    res2 = fake_tls.verify_client_hello(sid_empty, secret)
    assert res2 is not None
    cases.append({"client_hello": hx(sid_empty), "valid": True,
                  "client_random": hx(res2[0]),
                  "session_id": hx(res2[1]), "timestamp": res2[2]})
    write("fake_tls_verify.json", {"secret": hx(secret), "cases": cases})
    return secret, hello


# ---------------------------------------------------------------------------
# 7. parse_client_hello
# ---------------------------------------------------------------------------
def gen_fake_tls_parse(secret, hello):
    cases = []
    info = fake_tls.parse_client_hello(hello)
    cases.append({"input": hx(hello),
                  "cipher_suites": sorted(info.cipher_suites),
                  "key_shares": {str(k): v for k, v in info.key_shares.items()}})
    h = build_fake_client_hello(secret, int(time.time()), unhex("bb" * 32),
                                suites=(0x1301,),
                                key_shares=((0x11EC, 1216), (0x001D, 32)))
    info = fake_tls.parse_client_hello(h)
    cases.append({"input": hx(h),
                  "cipher_suites": sorted(info.cipher_suites),
                  "key_shares": {str(k): v for k, v in info.key_shares.items()}})
    bad = bytearray(hello)
    pos = 5 + 4 + 2 + 32
    pos += 1 + bad[pos]
    bad[pos:pos + 2] = b"\xff\xff"
    cases.append({"input": hx(bytes(bad)), "cipher_suites": [], "key_shares": {}})
    cases.append({"input": hx(hello[:60]), "cipher_suites": [], "key_shares": {}})
    write("fake_tls_parse.json", {"cases": cases})
    return h


# ---------------------------------------------------------------------------
# 8. build_server_hello with deterministic randomness
# ---------------------------------------------------------------------------
class DetRandomModule:
    """Stand-in for the `random` module imported inside fake_tls."""

    def __init__(self, src: ByteSource):
        self.src = src

    def uniform(self, a, b):
        u = int.from_bytes(self.src.randbytes(8), "big") / 2 ** 64
        return a + (b - a) * u

    def randint(self, a, b):
        u = int.from_bytes(self.src.randbytes(8), "big")
        return a + u % (b - a + 1)


def gen_server_hello(secret, hello, hybrid_hello):
    src = ByteSource(0xDEADBEEFCAFEBABE)
    real_urandom = os.urandom
    real_random = fake_tls.random
    os.urandom = lambda n, _s=src: _s.randbytes(n)
    fake_tls.random = DetRandomModule(src)
    try:
        cases = []
        for label, ch in (("plain", hello), ("hybrid", hybrid_hello)):
            info = fake_tls.parse_client_hello(ch)
            cr, sid, ts = fake_tls.verify_client_hello(ch, secret)
            sh = fake_tls.build_server_hello(secret, cr, sid, info)
            cases.append({"label": label, "client_random": hx(cr),
                          "session_id": hx(sid), "server_hello": hx(sh)})
        fake_tls.set_profiled_appdata_len(1234)
        info = fake_tls.parse_client_hello(hello)
        cr, sid, ts = fake_tls.verify_client_hello(hello, secret)
        sh = fake_tls.build_server_hello(secret, cr, sid, info)
        cases.append({"label": "profiled-1234", "client_random": hx(cr),
                      "session_id": hx(sid), "server_hello": hx(sh)})
        fake_tls.set_profiled_appdata_len(None)
    finally:
        os.urandom = real_urandom
        fake_tls.random = real_random
    write("fake_tls_serverhello.json",
          {"secret": hx(secret), "rng_seed": "0xDEADBEEFCAFEBABE",
           "note": "os.urandom + random.randint replaced by one shared xorshift64* stream; "
                   "randint(a,b)=a+u64%(b-a+1); key shares are RANDOM bytes in Python, so the "
                   ".NET check compares structure + HMAC tag, not the key bytes",
           "cases": cases})


# ---------------------------------------------------------------------------
# 9. wrap_tls_record
# ---------------------------------------------------------------------------
def gen_wrap():
    src = ByteSource(0x9E3779B97F4A7C15)
    lengths = [0, 1, 16383, 16384, 16385, 32768, 40000]
    cases = []
    for n in lengths:
        data = src.randbytes(n)
        cases.append({"input_len": n, "input": hx(data),
                      "output": hx(fake_tls.wrap_tls_record(data))})
    write("fake_tls_wrap.json", {"cases": cases})


def main():
    gen_aes()
    gen_handshakes()
    relay_cases = gen_relay_init()
    gen_crypto_ctx(relay_cases)
    gen_x25519()
    secret, hello = gen_fake_tls_verify()
    hybrid = gen_fake_tls_parse(secret, hello)
    gen_server_hello(secret, hello, hybrid)
    gen_wrap()


if __name__ == "__main__":
    main()
