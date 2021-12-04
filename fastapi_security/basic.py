import secrets
from base64 import urlsafe_b64encode
from typing import Dict, Iterable, List, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA512, Hash
from fastapi.security.http import HTTPBasicCredentials

__all__ = ("HTTPBasicCredentials", "generate_digest")


IterableOfHTTPBasicCredentials = Iterable[Union[HTTPBasicCredentials, Dict]]


class BasicAuthValidator:
    def __init__(self):
        self._credentials = []

    def init(self, credentials: IterableOfHTTPBasicCredentials):
        self._credentials = _make_credentials(credentials)

    def is_configured(self) -> bool:
        return len(self._credentials) > 0

    def validate(self, credentials: HTTPBasicCredentials) -> bool:
        if not self.is_configured():
            return False
        return any(
            (
                secrets.compare_digest(c.username, credentials.username)
                and secrets.compare_digest(c.password, credentials.password)
            )
            for c in self._credentials
        )


class BasicAuthWithDigestValidator:
    def __init__(self):
        self._credentials = []
        self._salt = None

    def init(self, credentials: IterableOfHTTPBasicCredentials, *, salt: str):
        self._credentials = _make_credentials(credentials)
        self._salt = salt

    def is_configured(self) -> bool:
        return self._salt and len(self._credentials) > 0

    def validate(self, credentials: HTTPBasicCredentials) -> bool:
        if not self.is_configured():
            return False
        return any(
            (
                secrets.compare_digest(c.username, credentials.username)
                and c.password == self.generate_digest(credentials.password)
            )
            for c in self._credentials
        )

    def generate_digest(self, secret: str):
        if not self._salt:
            raise ValueError(
                "BasicAuthWithDigestValidator: cannot generate digest, salt is empty"
            )
        return generate_digest(secret, salt=self._salt)


def _make_credentials(
    credentials: IterableOfHTTPBasicCredentials,
) -> List[HTTPBasicCredentials]:
    return [
        c if isinstance(c, HTTPBasicCredentials) else HTTPBasicCredentials(**c)
        for c in credentials
    ]


def generate_digest(secret: str, *, salt: str):
    hash_obj = Hash(algorithm=SHA512(), backend=default_backend())
    hash_obj.update((salt + secret).encode("latin1"))
    result = hash_obj.finalize()
    return urlsafe_b64encode(result).decode("latin1")
