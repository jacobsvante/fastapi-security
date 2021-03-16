import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

key = rsa.generate_private_key(
    backend=crypto_default_backend(), public_exponent=65537, key_size=2048
)

private_key = key.private_bytes(
    crypto_serialization.Encoding.PEM,
    crypto_serialization.PrivateFormat.PKCS8,
    crypto_serialization.NoEncryption(),
)
public_key_obj = key.public_key()
public_key = public_key_obj.public_bytes(
    crypto_serialization.Encoding.OpenSSH, crypto_serialization.PublicFormat.OpenSSH
)

_jwk = json.loads(RSAAlgorithm.to_jwk(public_key_obj))

dummy_alg = "RS256"
dummy_kid = "test123"
dummy_jwks_url = "https://identity-provider/.well-known/jwks.json"
dummy_audience = "https://some-resource"
dummy_jwks_response_data = {
    "keys": [
        {
            "alg": dummy_alg,
            "kty": _jwk["kty"],
            "use": "sig",
            "n": _jwk["n"],
            "e": _jwk["e"],
            "kid": dummy_kid,
        },
    ],
}
jwt_headers = {"alg": dummy_alg, "typ": "JWT", "kid": dummy_kid}


def make_access_token(
    *, sub: str, expire_in: int = 3600, **extra: Dict[str, Any]
) -> str:
    utcnow = datetime.now(tz=timezone.utc)
    expire_at = utcnow + timedelta(seconds=expire_in)

    data: Dict[str, Any] = {**extra}

    data["sub"] = sub
    data.setdefault("aud", dummy_audience)
    data.setdefault("iss", "https://identity-provider/")
    data.setdefault("iat", int(utcnow.timestamp()))
    data.setdefault("exp", int(expire_at.timestamp()))
    return jwt.encode(
        data,
        private_key.decode(),
        algorithm=dummy_alg,
        headers=jwt_headers,
    )
