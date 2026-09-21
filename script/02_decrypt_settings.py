import argparse
import sys
from pathlib import Path

def rc4(key: bytes, buf: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in buf:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

def main() -> int:
    ap = argparse.ArgumentParser(description="Decrypt Remcos SETTINGS (keylen||key||rc4)")
    ap.add_argument("settings_bin", type=Path, help="dumped SETTINGS blob")
    args = ap.parse_args()

    data = args.settings_bin.read_bytes()
    print("len", len(data))
    print("hex_head", data[:32].hex())

    klen = data[0]
    print("keylen", klen, hex(klen))
    if not (1 <= klen < len(data)):
        print("bad keylen", file=sys.stderr)
        return 1

    key, enc = data[1 : 1 + klen], data[1 + klen :]
    dec = rc4(key, enc)
    print("dec_head", dec[:80])
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in dec)
    print(text[:500])
    return 0

if __name__ == "__main__":
    raise SystemExit(main())