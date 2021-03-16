from aioresponses import aioresponses
from fastapi import Depends

from fastapi_security import FastAPISecurity, User, UserPermission

from .jwks_helpers import (
    dummy_audience,
    dummy_jwks_response_data,
    dummy_jwks_url,
    make_access_token,
)


def test_that_user_auth_data_is_returned_as_expected(app, client):

    security = FastAPISecurity()

    @app.get("/users/me")
    def get_user_info(user: User = Depends(security.authenticated_user_or_401)):
        return user.without_access_token().without_extra()

    security.init(app, jwks_url=dummy_jwks_url, audiences=[dummy_audience])

    access_token = make_access_token(sub="test-subject", scope=["email"])

    with aioresponses() as mock:
        mock.get(dummy_jwks_url, payload=dummy_jwks_response_data)

        resp = client.get(
            "/users/me", headers={"Authorization": f"Bearer {access_token}"}
        )
        assert resp.status_code == 200
        data = resp.json()["auth"]
        del data["expires_at"]
        del data["issued_at"]
        assert data == {
            "audience": ["https://some-resource"],
            "auth_method": "oauth2",
            "issuer": "https://identity-provider/",
            "permissions": [],
            "scopes": ["email"],
            "subject": "test-subject",
        }


def test_that_existing_permissions_are_added(app, client):

    security = FastAPISecurity()

    permission = UserPermission("users:list")  # noqa

    @app.get("/users/me")
    def get_user_info(user: User = Depends(security.authenticated_user_or_401)):
        return user.without_access_token().without_extra()

    security.init(app, jwks_url=dummy_jwks_url, audiences=[dummy_audience])

    access_token = make_access_token(
        sub="test-subject",
        permissions=["users:list"],
    )

    with aioresponses() as mock:
        mock.get(dummy_jwks_url, payload=dummy_jwks_response_data)

        resp = client.get(
            "/users/me", headers={"Authorization": f"Bearer {access_token}"}
        )
        assert resp.status_code == 200
        data = resp.json()["auth"]
        del data["expires_at"]
        del data["issued_at"]
        assert data == {
            "audience": ["https://some-resource"],
            "auth_method": "oauth2",
            "issuer": "https://identity-provider/",
            "permissions": ["users:list"],
            "scopes": [],
            "subject": "test-subject",
        }


def test_that_nonexisting_permissions_are_ignored(app, client):

    security = FastAPISecurity()

    @app.get("/users/me")
    def get_user_info(user: User = Depends(security.authenticated_user_or_401)):
        return user.without_access_token().without_extra()

    security.init(app, jwks_url=dummy_jwks_url, audiences=[dummy_audience])

    access_token = make_access_token(
        sub="test-subject",
        permissions=["users:list"],
    )

    with aioresponses() as mock:
        mock.get(dummy_jwks_url, payload=dummy_jwks_response_data)

        resp = client.get(
            "/users/me", headers={"Authorization": f"Bearer {access_token}"}
        )
        assert resp.status_code == 200
        data = resp.json()["auth"]
        del data["expires_at"]
        del data["issued_at"]
        assert data == {
            "audience": ["https://some-resource"],
            "auth_method": "oauth2",
            "issuer": "https://identity-provider/",
            "permissions": [],
            "scopes": [],
            "subject": "test-subject",
        }
