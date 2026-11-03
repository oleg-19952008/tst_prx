# Golden vectors (PORT_PLAN.md §6 items 3–4)

`gen_golden.py` regenerates the reference vectors used by
`tests/GoldenVectors.Tests` to prove the .NET crypto/FakeTLS port is
byte-for-byte compatible with the Python source (`tg-ws-proxy-main_py`).

Regenerate (requires Python ≥3.10 and `cryptography`, run from this folder):

```bash
PYTHONPATH=/path/to/tg-ws-proxy-main_py python3 gen_golden.py
```

## Files

| File | Covers | Determinism strategy |
|---|---|---|
| `aes_ctr.json` | `MtprotoAes` ≡ `Cipher(AES(key), CTR(iv)).encryptor().update()` — one-shot, chunked (incl. a 65-byte chunk that crosses a keystream block boundary) and byte-by-byte calls; AES-128/192/256 | fixed inputs |
| `obfs2_handshake.json` | `Obfuscated2.TryHandshake` ≡ `tg_ws_proxy._try_handshake`; also records `dec_key_sha256`, the 64-byte init keystream and the re-encrypted init for cross-checks | fixed inputs |
| `relay_init_fixed.json` | `Obfuscated2.GenerateRelayInit` ≡ `_generate_relay_init`: full xorshift draw log (including rejected draws) + `replays` block recomputed from the recorded output so the test can rebuild the exact input stream | `os.urandom` replaced by xorshift64\* seeded `0xFEEDFACE` |
| `crypto_ctx_streams.json` | `Obfuscated2.BuildCryptoContext` / `ReencryptUpstream/Downstream` ≡ `_build_crypto_ctx` + `CryptoCtx` round-trips; every stream key/IV and 64-byte keystream prefixes are recorded for granular failure isolation | fixed inputs |
| `x25519.json` | `Obfuscated2.X25519` raw scalar mult: RFC-style fixed scalars vs basepoint u=9, SHA-256-derived secret → public, random pairs (shared A→B == B→A) | fixed seeds |
| `fake_tls_verify.json` | `FakeTls.VerifyClientHello` ≡ `verify_client_hello`: valid (32-byte sid, empty sid, short sid ⇒ zero-filled), wrong secret, stale/future timestamp, truncated, bad record/handshake type | fixed inputs |
| `fake_tls_parse.json` | `FakeTls.ParseClientHello` ≡ `parse_client_hello`: suites/key_share extraction, duplicate groups (first wins), malformed ⇒ EMPTY, plus ClientHelloInfo-equality cases feeding `SelectCipherSuite` | fixed inputs |
| `fake_tls_serverhello.json` | `FakeTls.BuildServerHello` ≡ `build_server_hello` **byte-for-byte**: mlkem/x25519 shares, appdata length+payload and the HMAC server-random all drawn from ONE shared xorshift64\* stream (seed `0xDEADBEEFCAFEBABE`) in the documented call order; `X25519PrivateKey.generate` is monkeypatched to consume the same stream | see note field in JSON |
| `fake_tls_wrap.json` | `FakeTls.WrapTlsRecord` ≡ `wrap_tls_record` (0…40000 bytes) and `FirstAppDataRecordLen` ≡ `first_appdata_record_len` on wrapped data, real ServerHello flights, alert-first flight, incomplete record | fixed seed |

## Conventions the .NET tests must replicate

* **xorshift64\***: `state ^= state>>12; state = (state ^ (state<<25)) mod 2^64; state ^= state>>27; out = state * 0x2545F4914F6CDD1D mod 2^64`.
  `randbytes(n)` emits the 64-bit outputs as **big-endian 8-byte blocks**, truncated to `n`.
* **DetRandomModule.randint(a,b)** = `a + u64(next()) % (b-a+1)` (the generator only relies on it for `randint(64,160)`).
* The Python `proxy` package is imported unmodified — vectors always reflect the current source tree.
