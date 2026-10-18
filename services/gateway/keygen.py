"""Generate private/public RS256 dev keys locally. Never commit these files.

python -m services.gateway.keygen
"""

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_dev_keys(directory: Path = Path("runtime")) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    private_path = directory / "gateway-private.pem"
    public_path = directory / "gateway-public.pem"
    if private_path.exists() or public_path.exists():
        raise FileExistsError("Existing dev signing keys found; refusing to overwrite them")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    private_path.chmod(0o600)
    public_path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return private_path, public_path


if __name__ == "__main__":
    private, public = generate_dev_keys()
    print(f"Generated local development keys at {private} and {public}")
