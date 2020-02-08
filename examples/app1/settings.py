from functools import lru_cache
from typing import List

from fastapi.security import HTTPBasicCredentials
from pydantic import BaseSettings

__all__ = ("get_settings",)


class _Settings(BaseSettings):
    auth_jwks_url: str = None
    auth_audiences: List[str] = None
    basic_auth_credentials: List[HTTPBasicCredentials] = None
    oidc_discovery_url: str = None


@lru_cache()
def get_settings() -> _Settings:
    return _Settings()  # Reads variables from environment
