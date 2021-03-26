import logging

import aiohttp
import pytest
from aioresponses import aioresponses

from fastapi_security.entities import JwtAccessToken
from fastapi_security.oauth2 import Oauth2JwtAccessTokenValidator

from ..helpers.jwks import (
    dummy_audience,
    dummy_jwks_response_data,
    dummy_jwks_uri,
    dummy_jwt_headers,
    make_access_token,
)

pytestmark = pytest.mark.asyncio


async def test_that_jwt_cant_be_validated_when_uninitialized(caplog):
    caplog.set_level(logging.INFO)
    validator = Oauth2JwtAccessTokenValidator()
    # validator.init(dummy_jwks_uri, [dummy_audience])
    parsed = await validator.parse("abc")
    assert "JWT Access Token validator is not set up!" in caplog.text
    assert parsed is None


@pytest.mark.parametrize("empty_data", ((None, "", 0)))
async def test_that_empty_jwt_is_invalid(caplog, empty_data):
    caplog.set_level(logging.DEBUG)
    validator = Oauth2JwtAccessTokenValidator()
    validator.init(dummy_jwks_uri, [dummy_audience])
    parsed = await validator.parse(empty_data)
    assert "No JWT token provided" in caplog.text
    assert parsed is None


async def test_that_unparseable_token_is_invalid(caplog):
    caplog.set_level(logging.DEBUG)
    validator = Oauth2JwtAccessTokenValidator()
    validator.init(dummy_jwks_uri, [dummy_audience])
    parsed = await validator.parse("badDATA")
    assert (
        "Decoding unverified JWT token failed with error: DecodeError('Not enough segments"
        in caplog.text
    )
    assert parsed is None


async def test_that_missing_kid_field_is_invalid(caplog):
    caplog.set_level(logging.DEBUG)
    validator = Oauth2JwtAccessTokenValidator()
    validator.init(dummy_jwks_uri, [dummy_audience])
    token = make_access_token(sub="johndoe", headers={"alg": "RS256", "typ": "JWT"})
    parsed = await validator.parse(token)
    assert "No `kid` found in JWT token" in caplog.text
    assert parsed is None


async def test_that_mismatching_kid_field_fails(caplog):
    caplog.set_level(logging.DEBUG)
    validator = Oauth2JwtAccessTokenValidator()
    validator.init(dummy_jwks_uri, [dummy_audience])
    token = make_access_token(
        sub="johndoe",
        headers={"alg": "RS256", "typ": "JWT", "kid": "someother"},
    )

    with aioresponses() as mock:
        mock.get(dummy_jwks_uri, payload=dummy_jwks_response_data)
        parsed = await validator.parse(token)

    assert "No matching `kid` for JWT token" in caplog.text
    assert parsed is None


async def test_that_hs256_doesnt_work(caplog):
    caplog.set_level(logging.DEBUG)
    validator = Oauth2JwtAccessTokenValidator()
    validator.init(dummy_jwks_uri, [dummy_audience])
    token = make_access_token(
        sub="johndoe",
        headers={**dummy_jwt_headers, "alg": "HS256"},
    )

    with aioresponses() as mock:
        mock.get(dummy_jwks_uri, payload=dummy_jwks_response_data)
        parsed = await validator.parse(token)

    assert (
        "Decoding verified JWT token failed with error: InvalidAlgorithmError('The specified alg value is not allowed')"
        in caplog.text
    )
    assert parsed is None


async def test_that_missing_audience_fails(caplog):
    caplog.set_level(logging.DEBUG)
    validator = Oauth2JwtAccessTokenValidator()
    validator.init(dummy_jwks_uri, [dummy_audience])
    token = make_access_token(
        sub="johndoe",
        delete_fields=["aud"],
    )

    with aioresponses() as mock:
        mock.get(dummy_jwks_uri, payload=dummy_jwks_response_data)
        parsed = await validator.parse(token)

    assert (
        "Decoding verified JWT token failed with error: MissingRequiredClaimError('aud"
        in caplog.text
    )
    assert parsed is None


async def test_that_missing_expiry_date_fails(caplog):
    caplog.set_level(logging.DEBUG)
    validator = Oauth2JwtAccessTokenValidator()
    validator.init(dummy_jwks_uri, [dummy_audience])
    token = make_access_token(
        sub="johndoe",
        delete_fields=["exp"],
    )

    with aioresponses() as mock:
        mock.get(dummy_jwks_uri, payload=dummy_jwks_response_data)
        parsed = await validator.parse(token)

    assert (
        "Failed to parse JWT token with 1 validation error for JwtAccessToken\nexp\n  field required (type=value_error.missing)"
        in caplog.text
    )
    assert parsed is None


async def test_that_initial_failure_to_get_jwks_kid_data_raises_exception():
    validator = Oauth2JwtAccessTokenValidator()
    validator.init(dummy_jwks_uri, [dummy_audience])

    token = make_access_token(sub="johndoe")

    with pytest.raises(
        aiohttp.client_exceptions.ClientConnectorError,
        match="Cannot connect to host identity-provider:443",
    ):
        await validator.parse(token)


async def test_that_subsequent_failure_to_fetch_jwks_kid_data_is_handled(caplog):
    validator = Oauth2JwtAccessTokenValidator()
    validator.init(dummy_jwks_uri, [dummy_audience])

    token = make_access_token(sub="johndoe")

    with aioresponses() as mock:
        mock.get(dummy_jwks_uri, payload=dummy_jwks_response_data)
        await validator.parse(token)

    caplog.set_level(logging.INFO)

    # NOTE: Reaching into the internals to trigger JWKS kid data refresh
    validator._jwks_cached_at = -3600
    # NOTE: Not mocking JWKS endpoint, which would cause a "Cannot connect" error on
    #       the first try.
    parsed = await validator.parse(token)

    assert isinstance(parsed, JwtAccessToken)
    assert (
        "Failed to refresh JWKS kid mapping, re-using old data. Exception was: ClientConnectorError"
        in caplog.text
    )
