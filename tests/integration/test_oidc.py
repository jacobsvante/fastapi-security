from aioresponses import aioresponses
from fastapi import Depends

from fastapi_security import FastAPISecurity, User

from ..helpers.jwks import (
    dummy_audience,
    dummy_jwks_response_data,
    dummy_jwks_uri,
    make_access_token,
    skipif_oauth2_dependency_not_installed,
)
from ..helpers.oidc import dummy_oidc_url, dummy_userinfo_endpoint_url

pytestmark = skipif_oauth2_dependency_not_installed


def test_that_auth_can_be_enabled_through_oidc(app, client):

    security = FastAPISecurity()

    @app.get("/")
    def get_products(user: User = Depends(security.authenticated_user_or_401)):
        return []

    security.init_oauth2_through_oidc(dummy_oidc_url, audiences=[dummy_audience])

    access_token = make_access_token(sub="test-subject")

    with aioresponses() as mock:
        mock.get(
            dummy_oidc_url,
            payload={
                "userinfo_endpoint": dummy_userinfo_endpoint_url,
                "jwks_uri": dummy_jwks_uri,
            },
        )
        mock.get(dummy_jwks_uri, payload=dummy_jwks_response_data)
        mock.get(dummy_userinfo_endpoint_url, payload={"nickname": "jacobsvante"})

        unauthenticated_resp = client.get("/")
        assert unauthenticated_resp.status_code == 401

        authenticated_resp = client.get(
            "/", headers={"Authorization": f"Bearer {access_token}"}
        )
        assert authenticated_resp.status_code == 200


def test_that_oidc_info_is_returned(app, client):

    security = FastAPISecurity()

    @app.get("/users/me")
    async def get_user_details(user: User = Depends(security.user_with_info)):
        """Return user details, regardless of whether user is authenticated or not"""
        return user.without_access_token()

    security.init_oauth2_through_oidc(dummy_oidc_url, audiences=[dummy_audience])

    access_token = make_access_token(sub="test-subject")

    with aioresponses() as mock:
        mock.get(
            dummy_oidc_url,
            payload={
                "userinfo_endpoint": dummy_userinfo_endpoint_url,
                "jwks_uri": dummy_jwks_uri,
            },
        )
        mock.get(dummy_jwks_uri, payload=dummy_jwks_response_data)
        mock.get(dummy_userinfo_endpoint_url, payload={"nickname": "jacobsvante"})

        resp = client.get(
            "/users/me", headers={"Authorization": f"Bearer {access_token}"}
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["info"]["nickname"] == "jacobsvante"
