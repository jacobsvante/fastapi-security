import secrets
from typing import List, Optional

from fastapi.security.http import HTTPAuthorizationCredentials, HTTPBasicCredentials

__all__ = ("basic_auth",)


class BasicAuthValidator:
    def __init__(self):
        self._credentials = []

    def init(self, credentials: Optional[List[HTTPBasicCredentials]]):
        self._credentials = credentials or []

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


basic_auth = BasicAuthValidator()
