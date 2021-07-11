import secrets
from base64 import urlsafe_b64encode
from typing import Dict, Iterable, List, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA512, Hash

from fastapi.security.http import HTTPBasicCredentials

__all__ = ("HTTPBasicCredentials", "generate_digest")


from pydantic import BaseModel


class HTTPBasicCredentialsDigest(BaseModel):
    username: str
    digest: str


IterableOfHTTPBasicCredentials = Iterable[Union[HTTPBasicCredentials, Dict]]

IterableOfHTTPBasicCredentialsDigest = Iterable[
    Union[HTTPBasicCredentialsDigest, Dict]
]


class BasicAuthValidator:
    def __init__(self):
        self._credentials = []

    def init(self, credentials: IterableOfHTTPBasicCredentials):
        self._credentials = self._make_credentials(credentials)

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

    def _make_credentials(
        self, credentials: IterableOfHTTPBasicCredentials
    ) -> List[HTTPBasicCredentials]:
        return [
            c if isinstance(c, HTTPBasicCredentials) else HTTPBasicCredentials(**c)
            for c in credentials
        ]


class BasicAuthWithDigestValidator:
    def __init__(self):
        self._salt = None
        self._credentials = []

    def init(self, salt: str, credentials: IterableOfHTTPBasicCredentialsDigest):
        self._salt = salt
        self._credentials = self._make_credentials(credentials)

    def is_configured(self) -> bool:
        return self._salt and len(self._credentials) > 0

    def validate(self, credentials: HTTPBasicCredentials) -> bool:
        if not self.is_configured():
            return False
        return any(
            (
                secrets.compare_digest(c.username, credentials.username)
                and c.digest == self.generate_digest(self._salt, credentials.password)
            )
            for c in self._credentials
        )

    def generate_digest(self, secret: str):
        if not self._salt:
            raise ValueError('BasicAuthWithDigestValidator: cannot generate digest, salt is empty')
        return generate_digest(self._salt, secret)

    def _make_credentials(
        self, credentials: IterableOfHTTPBasicCredentialsDigest
    ) -> List[HTTPBasicCredentialsDigest]:
        return [
            c if isinstance(c, HTTPBasicCredentialsDigest) else HTTPBasicCredentialsDigest(**c)
            for c in credentials
        ]


def generate_digest(salt: str, secret: str):
    hash_obj = Hash(algorithm=SHA512(), backend=default_backend())
    hash_obj.update((salt + secret).encode('latin1'))
    result = hash_obj.finalize()
    return urlsafe_b64encode(result).decode('latin1')
