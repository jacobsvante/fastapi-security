from fastapi import Depends

from fastapi_security import FastAPISecurity, HTTPBasicCredentials, User
from fastapi_security.basic import BasicAuthValidator

from ..helpers.jwks import dummy_audience, dummy_jwks_uri


def test_that_basic_auth_doesnt_validate_any_credentials_if_unconfigured():
    validator = BasicAuthValidator()
    creds = HTTPBasicCredentials(username="johndoe", password="123")
    assert validator.validate(creds) is False


def test_that_uninitialized_basic_auth_doesnt_accept_any_credentials(app, client):
    security = FastAPISecurity()

    @app.get("/")
    def get_products(user: User = Depends(security.authenticated_user_or_401)):
        return []

    # NOTE: Not passing basic_auth_credentials, which means Basic Auth will be disabled
    # NOTE: We are passing
    security.init_oauth2_through_jwks(dummy_jwks_uri, audiences=[dummy_audience])

    resp = client.get("/")
    assert resp.status_code == 401

    resp = client.get("/", auth=("username", "password"))
    assert resp.status_code == 401


def test_that_basic_auth_rejects_incorrect_credentials(app, client):
    security = FastAPISecurity()

    @app.get("/")
    def get_products(user: User = Depends(security.authenticated_user_or_401)):
        return []

    credentials = [{"username": "user", "password": "pass"}]
    security.init_basic_auth(credentials)

    resp = client.get("/")
    assert resp.status_code == 401

    resp = client.get("/", auth=("user", ""))
    assert resp.status_code == 401

    resp = client.get("/", auth=("", "pass"))
    assert resp.status_code == 401

    resp = client.get("/", auth=("abc", "123"))
    assert resp.status_code == 401


def test_that_basic_auth_accepts_correct_credentials(app, client):
    security = FastAPISecurity()

    @app.get("/")
    def get_products(user: User = Depends(security.authenticated_user_or_401)):
        return []

    credentials = [{"username": "user", "password": "pass"}]
    security.init_basic_auth(credentials)

    resp = client.get("/", auth=("user", "pass"))
    assert resp.status_code == 200
