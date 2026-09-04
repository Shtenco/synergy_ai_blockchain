#!/usr/bin/env python3
"""Generate ML-DSA-87 and SLH-DSA-SHAKE-256s relayer keys locally."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from pqcrypto.sign import ml_dsa_87, slh_dsa_shake_256s


def write(path: Path, data: bytes, secret: bool) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    mode = 0o600 if secret else 0o644
    fd = os.open(path, flags, mode)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: generate_pq_relayer_keys.py <output-directory>")
    out = Path(sys.argv[1]).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(out, 0o700)

    ml_public, ml_secret = ml_dsa_87.keygen()
    slh_public, slh_secret = slh_dsa_shake_256s.keygen()

    write(out / "relayer.ml_dsa_87.pub", ml_public, False)
    write(out / "relayer.ml_dsa_87.key", ml_secret, True)
    write(out / "relayer.slh_dsa_shake_256s.pub", slh_public, False)
    write(out / "relayer.slh_dsa_shake_256s.key", slh_secret, True)

    print(f"generated PQ relayer keys in {out}")
    print("secret key files are mode 0600; do not commit this directory")


if __name__ == "__main__":
    main()
