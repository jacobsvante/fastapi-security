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


def test_that_authenticated_user_auth_data_is_returned_as_expected(app, client):

    security = FastAPISecurity()

    @app.get("/users/me")
    def get_user_info(user: User = Depends(security.authenticated_user_or_401)):
        return user.without_access_token()

    security.init_oauth2_through_jwks(dummy_jwks_uri, audiences=[dummy_audience])

    access_token = make_access_token(sub="test-subject", scope=["email"])

    with aioresponses() as mock:
        mock.get(dummy_jwks_uri, payload=dummy_jwks_response_data)

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


def test_that_user_dependency_works_authenticated_or_not(app, client):

    security = FastAPISecurity()

    @app.get("/users/me")
    def get_user_info(user: User = Depends(security.user)):
        return user.without_access_token()

    security.init_basic_auth([{"username": "JaneDoe", "password": "abc123"}])

    # Anonymous
    resp = client.get("/users/me")
    assert resp.status_code == 200
    data = resp.json()["auth"]
    del data["expires_at"]
    del data["issued_at"]
    assert data == {
        "audience": [],
        "auth_method": "none",
        "issuer": None,
        "permissions": [],
        "scopes": [],
        "subject": "anonymous",
    }

    # Authenticated
    resp = client.get("/users/me", auth=("JaneDoe", "abc123"))
    assert resp.status_code == 200
    data = resp.json()["auth"]
    del data["expires_at"]
    del data["issued_at"]
    assert data == {
        "audience": [],
        "auth_method": "basic_auth",
        "issuer": None,
        "permissions": [],
        "scopes": [],
        "subject": "JaneDoe",
    }


def test_that_user_with_info_dependency_works_unauthenticated(app, client):

    security = FastAPISecurity()

    @app.get("/users/me")
    def get_user_info(user: User = Depends(security.user_with_info)):
        return user.without_access_token()

    security.init_basic_auth([{"username": "a", "password": "b"}])

    resp = client.get("/users/me")
    assert resp.status_code == 200
    info = resp.json()["info"]
    assert info["nickname"] is None


def test_that_user_with_info_dependency_works_authenticated(app, client, caplog):
    import logging

    caplog.set_level(logging.DEBUG)
    security = FastAPISecurity()

    @app.get("/users/me")
    def get_user_info(user: User = Depends(security.user_with_info)):
        return user.without_access_token()

    security.init_oauth2_through_oidc(dummy_oidc_url, audiences=[dummy_audience])

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
        token = make_access_token(sub="GMqBbybGfBQeR6NgCY4NyXKnpFzaaTAn@clients")
        resp = client.get("/users/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.json()
        info = data["info"]
        assert info["nickname"] == "jacobsvante"


def test_that_authenticated_user_with_info_or_401_works_as_expected(app, client):
    security = FastAPISecurity()

    @app.get("/users/me")
    def get_user_info(
        user: User = Depends(security.authenticated_user_with_info_or_401),
    ):
        return user.without_access_token()

    security.init_oauth2_through_oidc(dummy_oidc_url, audiences=[dummy_audience])
    security.init_basic_auth([{"username": "a", "password": "b"}])

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
        token = make_access_token(sub="GMqBbybGfBQeR6NgCY4NyXKnpFzaaTAn@clients")
        resp = client.get("/users/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        info = resp.json()["info"]
        assert info["nickname"] == "jacobsvante"

        # Basic auth
        resp = client.get("/users/me", auth=("a", "b"))
        assert resp.status_code == 200
        info = resp.json()["info"]
        assert info["nickname"] is None

        # Unauthenticated
        resp = client.get("/users/me")
        assert resp.status_code == 401
        assert resp.json() == {"detail": "Could not validate credentials"}


def test_that_existing_permissions_are_added(app, client):

    security = FastAPISecurity()

    permission = security.user_permission("users:list")  # noqa

    @app.get("/users/me")
    def get_user_info(user: User = Depends(security.authenticated_user_or_401)):
        return user.without_access_token()

    security.init_oauth2_through_jwks(dummy_jwks_uri, audiences=[dummy_audience])

    access_token = make_access_token(
        sub="test-subject",
        permissions=["users:list"],
    )

    with aioresponses() as mock:
        mock.get(dummy_jwks_uri, payload=dummy_jwks_response_data)

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
        return user.without_access_token()

    security.init_oauth2_through_jwks(dummy_jwks_uri, audiences=[dummy_audience])

    access_token = make_access_token(
        sub="test-subject",
        permissions=["users:list"],
    )

    with aioresponses() as mock:
        mock.get(dummy_jwks_uri, payload=dummy_jwks_response_data)

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
