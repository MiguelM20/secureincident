"""One-time local container key initialization.

Run from project root (no other containers need to start):
    docker compose build
    docker compose run --rm --no-deps gateway python -m scripts.docker_init_keys

Gateway owns a private key volume. A separate public volume is mounted by the
Incident and Report services read-only. No signing key is built into an image.
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def initialize(private_path: Path, public_path: Path) -> None:
    if private_path == public_path:
        raise ValueError("Private and public key paths must differ")
    if private_path.exists() or public_path.exists():
        raise FileExistsError("Docker signing keys already exist; refusing to overwrite either key")

    private_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    public_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    newly_created = []
    try:
        # O_EXCL prevents replacing an existing key, including a symlink.
        for target, payload, mode in (
            (private_path, private_pem, 0o600),
            (public_path, public_pem, 0o644),
        ):
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
            newly_created.append(target)
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
    except Exception:
        for target in newly_created:
            target.unlink(missing_ok=True)
        raise


def main() -> None:
    private = os.environ.get("SECUREINCIDENT_PRIVATE_KEY_PATH")
    public = os.environ.get("SECUREINCIDENT_PUBLIC_KEY_PATH")
    if not private or not public:
        raise SystemExit("Gateway key paths must be configured by Docker Compose")
    initialize(Path(private), Path(public))
    print("Created Docker development signing keys in dedicated named volumes.")
    print("The private key is accessible only to Gateway; no secrets were printed.")


if __name__ == "__main__":
    main()
