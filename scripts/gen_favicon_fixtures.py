"""Generate favicon-hash fixtures for tests/favicon-hash.test.ts.

Shodan's favicon hash is mmh3.hash(base64.encodebytes(raw_bytes)): standard
base64 wrapped at 76 chars with a newline after every line (including the
last), hashed with MurmurHash3 x86_32, seed 0, as a signed int32.

Run: python -I scripts/gen_favicon_fixtures.py > tests/fixtures/favicon-hashes.json
Requires: pip install mmh3
"""
import base64
import hashlib
import json
import random

import mmh3

rng = random.Random(1337)


def case(name, data):
    b64 = base64.encodebytes(data)
    return {
        "name": name,
        "hex": data.hex(),
        "b64": b64.decode("ascii"),
        "mmh3": mmh3.hash(b64),
        "mmh3_raw": mmh3.hash(data),
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


cases = [
    case("empty", b""),
    case("one byte", b"\x00"),
    case("hello", b"hello"),
    case("57 bytes (exactly one 76-char line)", bytes(range(57))),
    case("58 bytes (wraps to a second line)", bytes(range(58))),
    case("tail 1", b"abcde"),
    case("tail 2", b"abcdef"),
    case("tail 3", b"abcdefg"),
    case("high bytes", bytes([0xFF, 0xFE, 0x80, 0x7F] * 9)),
    case("random 1 KiB", bytes(rng.getrandbits(8) for _ in range(1024))),
    case("random 5 KiB", bytes(rng.getrandbits(8) for _ in range(5 * 1024 + 3))),
]

# Raw mmh3 test vectors (no base64), to validate the hash on its own.
raw = [
    {"hex": s.encode().hex(), "seed": seed, "mmh3": mmh3.hash(s.encode(), seed)}
    for s, seed in [
        ("", 0),
        ("", 1),
        ("a", 0),
        ("ab", 0),
        ("abc", 0),
        ("abcd", 0),
        ("Hello, world!", 0),
        ("The quick brown fox jumps over the lazy dog", 0),
        ("The quick brown fox jumps over the lazy dog", 0x9747B28C),
    ]
]

print(json.dumps({"generator": "python mmh3 " + getattr(mmh3, "__version__", "?"), "favicon": cases, "raw": raw}, indent=1))
