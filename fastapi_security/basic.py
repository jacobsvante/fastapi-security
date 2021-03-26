import secrets
from typing import Dict, Iterable, List, Union

from fastapi.security.http import HTTPBasicCredentials

__all__ = ("HTTPBasicCredentials",)

IterableOfHTTPBasicCredentials = Iterable[Union[HTTPBasicCredentials, Dict]]


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
