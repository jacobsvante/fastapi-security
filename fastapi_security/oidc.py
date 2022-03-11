import logging
import time
from typing import Any, Dict, Optional

from ._optional_dependencies import aiohttp
from .entities import UserInfo
from .exceptions import MissingDependency

logger = logging.getLogger(__name__)


DEFAULT_DISCOVERY_RESPONSE_CACHE_PERIOD = 3600  # 1 hour


class OpenIdConnectDiscovery:
    """Retrieve info from OpenID Connect (OIDC) endpoints"""

    def __init__(self):
        self._discovery_url: Optional[str] = None
        self._discovery_data_cached_at: Optional[float] = None
        self._discovery_cache_period: float = float(
            DEFAULT_DISCOVERY_RESPONSE_CACHE_PERIOD
        )
        self._discovery_data: Optional[Dict[str, Any]] = None

    def init(
        self,
        discovery_url: str,
        *,
        discovery_cache_period: int = DEFAULT_DISCOVERY_RESPONSE_CACHE_PERIOD,
    ):
        """Set up OpenID Connect data fetching

        Args:
            discovery_url:
                The well-known OpenID Connect discovery endpoint
                Example: "https://domain/.well-known/openid-connect"
            discovery_cache_period:
                How many seconds to cache the OpenID Discovery endpoint response. Defaults to 1 hour.
        """
        if aiohttp is None:
            raise MissingDependency(
                "`aiohttp` dependency not installed, ensure its availability with `pip install fastapi-security[oauth2]`"
            )
        self._discovery_url = discovery_url
        self._discovery_cache_period = float(discovery_cache_period)

    def is_configured(self) -> bool:
        return bool(self._discovery_url)

    async def get_user_info(self, access_token: str) -> Optional[UserInfo]:
        """Get user info for the given OAuth 2 access token

        Returns a parsed UserInfo object on successful verification,
        otherwise `None`.
        """
        if not self.is_configured():
            logger.info("OpenID Connect discovery URL is not set up!")
            return None

        if not access_token:
            logger.debug("No access token provided")
            return None

        user_info = await self._fetch_user_info(access_token)

        if user_info is None:
            return UserInfo.make_dummy()
        else:
            return UserInfo.from_oidc_endpoint(user_info)

    async def get_jwks_uri(self) -> str:
        """Get or fetch the JWKS URI"""
        data = await self.get_discovery_data()
        return data["jwks_uri"]

    async def _fetch_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        timeout = aiohttp.ClientTimeout(total=10)
        url = await self.get_user_info_endpoint()
        headers = {"Authorization": f"Bearer {access_token}"}

        logger.debug(f"Fetching user info from {url}")

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    logger.debug(
                        "User info could not be fetched (might be a machine user)"
                    )
                    return None

    async def get_user_info_endpoint(self) -> str:
        data = await self.get_discovery_data()
        return data["userinfo_endpoint"]

    async def get_discovery_data(self) -> Dict[str, Any]:
        if (
            self._discovery_data is None
            or self._discovery_data_cached_at is None
            or (
                (time.monotonic() - self._discovery_data_cached_at)
                > self._discovery_cache_period
            )
        ):
            try:
                self._discovery_data = await self._fetch_discovery_data()
            except Exception as ex:
                if self._discovery_data is None:
                    raise
                else:
                    logger.info(
                        f"Failed to refresh OIDC discovery data, re-using old data. "
                        f"Exception was: {ex!r}"
                    )
                    self._discovery_data_cached_at = time.monotonic()
            else:
                self._discovery_data_cached_at = time.monotonic()

        return self._discovery_data

    async def _fetch_discovery_data(self) -> Dict[str, Any]:
        timeout = aiohttp.ClientTimeout(total=10)
        assert self._discovery_url, "No OIDC discovery URL specified"

        logger.debug(f"Fetching OIDC discovery data from {self._discovery_url}")

        async with aiohttp.ClientSession(timeout=timeout, raise_for_status=True) as s:
            async with s.get(self._discovery_url) as response:
                return await response.json()
