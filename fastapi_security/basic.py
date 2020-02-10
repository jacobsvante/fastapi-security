import secrets
from typing import Dict, List, Union

from fastapi.security.http import HTTPAuthorizationCredentials, HTTPBasicCredentials

__all__ = ()

ListOfCredentials = List[Union[HTTPBasicCredentials, Dict]]


class BasicAuthValidator:
    def __init__(self):
        self._credentials = []

    def init(self, credentials: ListOfCredentials):
        self._credentials = self._make_credentials(credentials)

    def is_configured(self) -> bool:
        return len(self._credentials) > 0

    def validate(self, credentials: HTTPAuthorizationCredentials) -> bool:
        if not self.is_configured():
            return False
        return any(
            (
                secrets.compare_digest(c.username, credentials.username)
                and secrets.compare_digest(c.password, credentials.password)
            )
            for c in self._credentials
        )

    def _make_credentials(self, credentials: ListOfCredentials):
        return [
            c if isinstance(c, HTTPBasicCredentials) else HTTPBasicCredentials(**c)
            for c in credentials
        ]
