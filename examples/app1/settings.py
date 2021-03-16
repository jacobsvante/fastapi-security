from functools import lru_cache
from typing import Dict, List, Optional

from fastapi.security import HTTPBasicCredentials
from pydantic import BaseSettings

__all__ = ("get_settings",)


class _Settings(BaseSettings):
    oauth2_jwks_url: Optional[
        str
    ] = None  # TODO: This could be retrieved from OIDC discovery URL
    oauth2_audiences: Optional[List[str]] = None
    basic_auth_credentials: Optional[List[HTTPBasicCredentials]] = None
    oidc_discovery_url: Optional[str] = None
    permission_overrides: Optional[Dict[str, List[str]]] = None


@lru_cache()
def get_settings() -> _Settings:
    return _Settings()  # Reads variables from environment
