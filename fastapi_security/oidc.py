import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import aiohttp

from .entities import UserInfo

logger = logging.getLogger(__name__)


DEFAULT_DISCOVERY_RESPONSE_CACHE_PERIOD = 3600  # 1 hour


class OpenIdConnectDiscovery:
    """Retrieve info from OpenID Connect (OIDC) endpoints"""

    def __init__(self):
        self._discovery_url = None
        self._discovery_cache_period = DEFAULT_DISCOVERY_RESPONSE_CACHE_PERIOD

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
        self._discovery_url = discovery_url
        self._discovery_cache_period = discovery_cache_period
        self._discovery_data_cached_at = None
        self._discovery_data = None

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

    async def _fetch_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        timeout = aiohttp.ClientTimeout(total=10)
        url = await self._get_user_info_endpoint()
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

    async def _get_user_info_endpoint(self) -> str:
        data = await self._get_discovery_data()
        return data["userinfo_endpoint"]

    async def _get_discovery_data(self) -> Dict[str, Any]:
        if self._discovery_data_cached_at is None or (
            (datetime.utcnow() - self._discovery_data_cached_at)
            > timedelta(seconds=self._discovery_cache_period)
        ):
            self._discovery_data = await self._fetch_discovery_data()
            self._discovery_data_cached_at = datetime.utcnow()

        return self._discovery_data

    async def _fetch_discovery_data(self):
        timeout = aiohttp.ClientTimeout(total=10)

        logger.debug(f"Fetching OIDC discovery data from {self._discovery_url}")

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(self._discovery_url) as response:
                return await response.json()
