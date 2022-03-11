import logging

import aiohttp
import pytest
from aioresponses import aioresponses

from fastapi_security.oidc import OpenIdConnectDiscovery

from ..helpers.jwks import make_access_token, skipif_oauth2_dependency_not_installed
from ..helpers.oidc import dummy_oidc_url, dummy_userinfo_endpoint_url

pytestmark = [
    pytest.mark.asyncio,
    skipif_oauth2_dependency_not_installed,
]


async def test_that_getting_user_info_doesnt_work_uninitialized(caplog):
    caplog.set_level(logging.INFO)
    token = make_access_token(sub="janedoe")
    oidc = OpenIdConnectDiscovery()
    user_info = await oidc.get_user_info(token)
    assert user_info is None
    assert "OpenID Connect discovery URL is not set up!" in caplog.text


async def test_that_getting_user_info_with_empty_access_token_doesnt_work(caplog):
    caplog.set_level(logging.DEBUG)
    oidc = OpenIdConnectDiscovery()
    oidc.init(dummy_oidc_url)
    user_info = await oidc.get_user_info("")
    assert user_info is None
    assert "No access token provided" in caplog.text


@skipif_oauth2_dependency_not_installed
async def test_that_dummy_user_info_is_returned_when_endpoint_returns_non_200(caplog):
    caplog.set_level(logging.DEBUG)
    oidc = OpenIdConnectDiscovery()
    oidc.init(dummy_oidc_url)
    token = make_access_token(sub="JaneDoe")

    with aioresponses() as mock:
        mock.get(
            dummy_oidc_url,
            payload={"userinfo_endpoint": dummy_userinfo_endpoint_url},
        )
        mock.get(dummy_userinfo_endpoint_url, status=503)

        user_info = await oidc.get_user_info(token)

    assert all(v is None for v in user_info.dict().values())


async def test_that_initial_failure_to_fetch_discovery_data_raises_exception():
    oidc = OpenIdConnectDiscovery()
    oidc.init(dummy_oidc_url)

    with pytest.raises(
        aiohttp.client_exceptions.ClientConnectorError,
        match="Cannot connect to host oidc-provider:443",
    ):
        await oidc.get_discovery_data()


async def test_that_subsequent_failure_to_fetch_discovery_data_is_handled(caplog):
    oidc = OpenIdConnectDiscovery()
    oidc.init(dummy_oidc_url)

    with aioresponses() as mock:
        mock.get(
            dummy_oidc_url, payload={"userinfo_endpoint": dummy_userinfo_endpoint_url}
        )
        await oidc.get_discovery_data()

    caplog.set_level(logging.INFO)

    # NOTE: Reaching into the internals to trigger JWKS kid data refresh
    oidc._discovery_data_cached_at = -3600
    # NOTE: Not mocking JWKS endpoint, which would cause a "Cannot connect" error on
    #       the first try.
    parsed = await oidc.get_discovery_data()

    assert parsed == {"userinfo_endpoint": dummy_userinfo_endpoint_url}
    assert (
        "Failed to refresh OIDC discovery data, re-using old data. Exception was: ClientConnectorError"
        in caplog.text
    )
