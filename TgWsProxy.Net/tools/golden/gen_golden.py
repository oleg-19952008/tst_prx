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
    HANDSHAKE_LEN, SKIP_LEN, PREKEY_LEN, KEY_LEN, IV_LEN, PROTO_TAG_POS,
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


def replay_relay_init(proto_tag: bytes, dc_idx: int, relay_init: bytes) -> dict:
    """Recompute _generate_relay_init from the recorded output bytes.

    relay_init[8:40] is the AES key, [40:56] the IV; the keystream tail
    (relay_init[56:64] XOR rnd[56:64]) lets us recover the two random bytes
    appended after (proto_tag, dc_idx). A .NET implementation fed the same
    stream must reproduce relay_init byte-for-byte.
    """
    enc_key = relay_init[SKIP_LEN:SKIP_LEN + PREKEY_LEN]
    enc_iv = relay_init[SKIP_LEN + PREKEY_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN]
    # keystream_tail[i] = encrypted_full[56+i] ^ rnd[56+i]; encrypted_full is
    # AES-CTR(key,iv) over relay_init treated as plaintext-rnd.
    ks_full = Cipher(algorithms.AES(enc_key), modes.CTR(enc_iv)).encryptor() \
        .update(relay_init)
    keystream_tail = bytes(ks_full[PROTO_TAG_POS + i] ^ relay_init[PROTO_TAG_POS + i]
                           for i in range(8))
    tail_plain = bytes(relay_init[PROTO_TAG_POS + i] ^ keystream_tail[i]
                       for i in range(8))
    assert tail_plain[:4] == proto_tag
    assert struct.unpack("<h", tail_plain[4:6])[0] == dc_idx
    return {
        "proto_tag": hx(proto_tag),
        "dc_idx": dc_idx,
        "relay_init": hx(relay_init),
        "enc_key": hx(enc_key),
        "enc_iv": hx(enc_iv),
        "keystream_tail": hx(keystream_tail),
        "tail_random_2b": hx(tail_plain[6:8]),
    }


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
        pt_src.randbytes(65),
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
        dec_key = hashlib.sha256(prekey + secret).digest()
        ks64 = Cipher(algorithms.AES(dec_key), modes.CTR(iv)).encryptor() \
            .update(bytes(HANDSHAKE_LEN))
        out["cases"].append({
            "handshake": hx(hs),
            "dc_id": res[0], "is_media": res[1],
            "proto_tag": hx(res[2]),
            "dec_prekey_and_iv": hx(res[3]),
            "wrong_secret_returns_none": bad is None,
            "dec_key_sha256": hx(dec_key),
            "keystream_64": hx(ks64),
            "client_init_reencrypted": hx(bytes(a ^ b for a, b in zip(hs, ks64))),
        })
    out["cases"].append({"handshake": hx(unhex(out["cases"][0]["handshake"])[:63]),
                         "expect_none": True})
    write("obfs2_handshake.json", out)


# ---------------------------------------------------------------------------
# 3. relay init generation with fixed RNG (os.urandom monkeypatched)
# ---------------------------------------------------------------------------
class RecordingByteSource(ByteSource):
    """ByteSource that remembers every randbytes() call for replay vectors."""

    def __init__(self, seed: int):
        super().__init__(seed)
        self.log = []

    def randbytes(self, n: int) -> bytes:
        b = super().randbytes(n)
        self.log.append(hx(b))
        return b


def gen_relay_init():
    urandom = os.urandom
    src = RecordingByteSource(0xFEEDFACE)
    os.urandom = lambda n, _s=src: _s.randbytes(n)
    try:
        cases = []
        for proto, dc in [(PROTO_TAG_ABRIDGED, 2), (PROTO_TAG_INTERMEDIATE, 4),
                          (PROTO_TAG_SECURE, -5), (PROTO_TAG_SECURE, 10002)]:
            before = len(src.log)
            ri = _generate_relay_init(proto, dc)
            draws = src.log[before:]
            accepted = [d for d in draws if len(d) == HANDSHAKE_LEN * 2][-1]
            cases.append({"proto_tag": hx(proto), "dc_idx": dc, "relay_init": hx(ri),
                          "draws": draws, "accepted_rnd": accepted})
    finally:
        os.urandom = urandom
    replays = [replay_relay_init(unhex(c["proto_tag"]), c["dc_idx"],
                                 unhex(c["relay_init"])) for c in cases]
    write("relay_init_fixed.json",
          {"note": "os.urandom replaced by xorshift64* stream seeded 0xFEEDFACE; "
                   "rejection loop consumes 64-byte draws until first byte != 0xEF, "
                   "starts not in RESERVED_STARTS and rnd[4:8] != 0000",
           "cases": cases, "replays": replays})
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
        piv = res[3]
        clt_dec_key = hashlib.sha256(piv[:PREKEY_LEN] + secret).digest()
        clt_enc_piv = piv[::-1]
        clt_enc_key = hashlib.sha256(clt_enc_piv[:PREKEY_LEN] + secret).digest()
        relay_enc_key = relay_init[SKIP_LEN:SKIP_LEN + PREKEY_LEN]
        relay_enc_iv = relay_init[SKIP_LEN + PREKEY_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN]
        relay_dec_piv = relay_init[SKIP_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN][::-1]

        def ks(key, iv, n):
            return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor().update(bytes(n))

        ctx = _build_crypto_ctx(piv, secret, relay_init)
        blobs = [fill.randbytes(300), fill.randbytes(1)]
        out["cases"].append({
            "handshake": hx(handshake),
            "relay_init": hx(relay_init),
            "clt_dec_key": hx(clt_dec_key), "clt_dec_iv": hx(piv[PREKEY_LEN:]),
            "clt_enc_key": hx(clt_enc_key), "clt_enc_iv": hx(clt_enc_piv[PREKEY_LEN:]),
            "tg_enc_key": hx(relay_enc_key), "tg_enc_iv": hx(relay_enc_iv),
            "tg_dec_key": hx(relay_dec_piv[:KEY_LEN]), "tg_dec_iv": hx(relay_dec_piv[KEY_LEN:]),
            "clt_dec_ks_after_init": hx(ks(clt_dec_key, piv[PREKEY_LEN:], 128)),
            "clt_enc_ks_first64": hx(ks(clt_enc_key, clt_enc_piv[PREKEY_LEN:], 64)),
            "tg_enc_ks_after_init": hx(ks(relay_enc_key, relay_enc_iv, 128)),
            "tg_dec_ks_first64": hx(ks(relay_dec_piv[:KEY_LEN], relay_dec_piv[KEY_LEN:], 64)),
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
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
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
    # Fixed private scalars exchanged against the basepoint u=9; the .NET port
    # must reproduce public_a/shared_ab exactly (RFC 7748 clamping semantics).
    for name, priv in [
        ("fixed-scalar-1", "a546e3bf8905c07bd1ab72eeb8efef152daba724eb3bbf4e61aedc9dc5840015"),
        ("fixed-scalar-2", "4b09f9d24432915b08ac3cb0a4fb0dbf84608ad71a237b3503ea181f6cacda50"),
    ]:
        k = X25519PrivateKey.from_private_bytes(unhex(priv))
        upk = X25519PublicKey.from_public_bytes(b'\x09' + bytes(31))
        vecs.append({"name": name + "-vs-basepoint9", "private_a": priv,
                     "public_a": hx(k.public_key().public_bytes_raw()),
                     "peer_pub": "09" + "00" * 31,
                     "shared_ab": hx(k.exchange(upk))})
    # obfuscated2-style derived secret -> public (fixed input, checked in .NET)
    derived = hashlib.sha256(b"tg-ws-proxy golden x25519 seed").digest()
    dk = X25519PrivateKey.from_private_bytes(derived)
    vecs.append({"name": "derived-sha256-seed", "private_a": hx(derived),
                 "public_a": hx(dk.public_key().public_bytes_raw())})

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
    future = build_fake_client_hello(secret, now + 1000, sid)
    cases.append({"client_hello": hx(future), "expect_none": True})
    short_sid = build_fake_client_hello(secret, now, unhex("dd" * 8))
    res3 = fake_tls.verify_client_hello(short_sid, secret)
    assert res3 is not None and res3[1] == bytes(32)
    cases.append({"client_hello": hx(short_sid), "valid": True,
                  "client_random": hx(res3[0]),
                  "session_id": hx(res3[1]), "timestamp": res3[2]})
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
    cases.append({"input": hx(bytes(bad)), "cipher_suites": [], "key_shares": {},
                  "expect_empty_info": True})
    cases.append({"input": hx(hello[:60]), "cipher_suites": [], "key_shares": {},
                  "expect_empty_info": True})
    # suite-selection inputs (ClientHelloInfo equality check in .NET)
    suites_only = []
    for offered in [(0x1302,), (0x1303, 0x1302), (0xc02f,), (),
                    (0x1301, 0x1303)]:
        hh = build_fake_client_hello(secret, int(time.time()), unhex("cc" * 32),
                                     suites=offered or (0x1301,),
                                     key_shares=((0x001D, 32),))
        if not offered:
            hh = build_fake_client_hello(secret, int(time.time()), unhex("cc" * 32),
                                         suites=(0x1301,), key_shares=((0x001D, 32),))
        info = fake_tls.parse_client_hello(hh)
        suites_only.append({"input": hx(hh),
                            "cipher_suites": sorted(info.cipher_suites),
                            "key_shares": {str(k): v for k, v in info.key_shares.items()},
                            "expected_info": [sorted(offered) or [0x1301],
                                              {str(0x001D): 32}]})
    cases.extend(suites_only)
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


class DetX25519Key:
    """Deterministic stand-in for X25519PrivateKey.generate() during golden runs."""

    def __init__(self, pub: bytes):
        self._pub = pub

    def public_key(self):
        return self

    def public_bytes_raw(self):
        return self._pub


class DetX25519Module:
    def __init__(self, src: ByteSource):
        self.src = src

    class _Factory:
        def __init__(self, src):
            self.src = src

        def generate(self):
            return DetX25519Key(self.src.randbytes(32))

    @property
    def X25519PrivateKey(self):  # pragma: no cover - not used
        raise NotImplementedError


def gen_server_hello(secret, hello, hybrid_hello):
    src = ByteSource(0xDEADBEEFCAFEBABE)
    real_urandom = os.urandom
    real_random = fake_tls.random
    real_xkey = fake_tls.X25519PrivateKey
    factory = DetX25519Module._Factory(src)
    os.urandom = lambda n, _s=src: _s.randbytes(n)
    fake_tls.random = DetRandomModule(src)
    fake_tls.X25519PrivateKey = factory
    try:
        cases = []
        import struct as _st

        def describe(label, ch, expect_x25519_pub=None, expect_mlkem=None,
                     expect_appdata_len=None, expect_app_payload=None):
            info = fake_tls.parse_client_hello(ch)
            cr, sid, ts = fake_tls.verify_client_hello(ch, secret)
            sh = fake_tls.build_server_hello(secret, cr, sid, info)
            zeroed = bytearray(sh)
            zeroed[11:43] = bytes(32)
            tag = hmac.new(secret, cr + bytes(zeroed), hashlib.sha256).digest()
            assert tag == sh[11:43], "server random must be HMAC over zeroed response"
            # walk records: handshake, ccs, appdata
            recs = []
            pos = 0
            while pos + 5 <= len(sh):
                rtype = sh[pos]
                rlen = _st.unpack_from(">H", sh, pos + 3)[0]
                recs.append([rtype, rlen])
                pos += 5 + rlen
            hs_body_len = _st.unpack_from(">I", b"\x00" + sh[6:9], 0)[0]
            cases.append({"label": label, "client_random": hx(cr),
                          "session_id": hx(sid), "server_hello": hx(sh),
                          "records": recs, "hs_message_len": hs_body_len,
                          "appdata_len": recs[-1][1] if recs and recs[-1][0] == 0x17 else None,
                          "tag_ok": True,
                          "expect_x25519_pub": expect_x25519_pub,
                          "expect_mlkem": expect_mlkem,
                          "expect_appdata_len": expect_appdata_len,
                          "expect_app_payload": expect_app_payload})
            # verify the recorded response really equals the predicted stream
            if expect_x25519_pub is not None:
                assert expect_x25519_pub in hx(sh), "x25519 share mismatch"
            if expect_mlkem is not None:
                assert expect_mlkem in hx(sh), "mlkem share mismatch"
            if expect_app_payload is not None:
                alen = expect_appdata_len
                assert hx(sh[-alen:]) == expect_app_payload, "appdata payload mismatch"
                assert recs[-1][1] == alen, "appdata len mismatch"

        # Expected draws: replay the shared xorshift stream with the SAME call
        # order as build_server_hello uses (urandom/randint/generate all read
        # from one stream; the stream is NOT reset between cases).
        class Predict:
            def __init__(self):
                self.s = ByteSource(0xDEADBEEFCAFEBABE)

            def plain(self):
                pub = self.s.randbytes(32)
                alen = 64 + int.from_bytes(self.s.randbytes(8), "big") % 97
                payload = self.s.randbytes(alen)
                return {"x25519_pub": hx(pub), "mlkem": None,
                        "appdata_len": alen, "app_payload": hx(payload)}

            def hybrid(self):
                mlkem = self.s.randbytes(1088)
                pub = self.s.randbytes(32)
                alen = 64 + int.from_bytes(self.s.randbytes(8), "big") % 97
                payload = self.s.randbytes(alen)
                return {"x25519_pub": hx(pub), "mlkem": hx(mlkem),
                        "appdata_len": alen, "app_payload": hx(payload)}

            def profiled(self, length):
                pub = self.s.randbytes(32)
                payload = self.s.randbytes(length)
                return {"x25519_pub": hx(pub), "mlkem": None,
                        "appdata_len": length, "app_payload": hx(payload)}

        pr = Predict()
        e = pr.plain()
        describe("plain", hello, expect_x25519_pub=e["x25519_pub"],
                 expect_appdata_len=e["appdata_len"], expect_app_payload=e["app_payload"])
        e = pr.hybrid()
        describe("hybrid", hybrid_hello, expect_x25519_pub=e["x25519_pub"],
                 expect_mlkem=e["mlkem"], expect_appdata_len=e["appdata_len"],
                 expect_app_payload=e["app_payload"])
        fake_tls.set_profiled_appdata_len(1234)
        e = pr.profiled(1234)
        describe("profiled-1234", hello, expect_x25519_pub=e["x25519_pub"],
                 expect_appdata_len=e["appdata_len"], expect_app_payload=e["app_payload"])
        fake_tls.set_profiled_appdata_len(None)
    finally:
        os.urandom = real_urandom
        fake_tls.random = real_random
        fake_tls.X25519PrivateKey = real_xkey
    write("fake_tls_serverhello.json",
          {"secret": hx(secret), "rng_seed": "DEADBEEFCAFEBABE",
           "note": "os.urandom, random.randint AND X25519 key generation all draw from ONE "
                   "shared xorshift64* stream seeded 0xDEADBEEFCAFEBABE, in this order per "
                   "build_server_hello call: (hybrid only) mlkem=urandom(1088); x25519 "
                   "key_share = generate()->randbytes(32) raw bytes (NOT a curve point - "
                   "deterministic stand-in); appdata_len=random.randint(64,160) as "
                   "64+u64%97 over the next 8 big-endian bytes; app_payload=urandom(len). "
                   "The .NET test replays the identical stream and must match byte-for-byte.",
           "cases": cases})


# ---------------------------------------------------------------------------
# 9. wrap_tls_record
# ---------------------------------------------------------------------------
def gen_wrap(serverhello_cases=None):
    src = ByteSource(0x9E3779B97F4A7C15)
    lengths = [0, 1, 16383, 16384, 16385, 32768, 40000]
    cases = []
    for n in lengths:
        data = src.randbytes(n)
        out = fake_tls.wrap_tls_record(data)
        assert fake_tls.first_appdata_record_len(out) == (min(n, 16384) or None)
        cases.append({"input_len": n, "input": hx(data), "output": hx(out)})
    extra = []
    if serverhello_cases:
        for c in serverhello_cases:
            sh = unhex(c["server_hello"])
            fl = fake_tls.first_appdata_record_len(sh)
            extra.append({"input": c["server_hello"], "first_appdata_len": fl})
        alert = b"\x15\x03\x03\x00\x02\x02\x28" + b"\x17\x03\x03\x00\x10" + bytes(16)
        extra.append({"input": hx(alert), "first_appdata_len":
                      fake_tls.first_appdata_record_len(alert)})
        partial = b"\x16\x03\x03\x00\x64" + bytes(20)  # incomplete record
        extra.append({"input": hx(partial), "first_appdata_len":
                      fake_tls.first_appdata_record_len(partial)})
    write("fake_tls_wrap.json", {"cases": cases, "first_appdata": extra})


def main():
    gen_aes()
    gen_handshakes()
    relay_cases = gen_relay_init()
    gen_crypto_ctx(relay_cases)
    gen_x25519()
    secret, hello = gen_fake_tls_verify()
    hybrid = gen_fake_tls_parse(secret, hello)
    sh_cases = gen_server_hello(secret, hello, hybrid)
    gen_wrap(sh_cases)


if __name__ == "__main__":
    main()
