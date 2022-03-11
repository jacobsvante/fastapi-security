from aioresponses import aioresponses
from fastapi import Depends

from fastapi_security import FastAPISecurity, User

from ..helpers.jwks import (
    dummy_audience,
    dummy_jwks_response_data,
    dummy_jwks_uri,
    skipif_oauth2_dependency_not_installed,
)


def test_that_header_is_returned_for_basic_auth(app, client):
    security = FastAPISecurity()
    security.init_basic_auth([{"username": "user", "password": "pass"}])

    @app.get("/")
    def get_products(user: User = Depends(security.authenticated_user_or_401)):
        return []

    resp = client.get("/")
    assert resp.headers["WWW-Authenticate"] == "Basic"


@skipif_oauth2_dependency_not_installed
def test_that_header_is_returned_for_oauth2(app, client):
    security = FastAPISecurity()
    security.init_oauth2_through_jwks(dummy_jwks_uri, audiences=[dummy_audience])

    @app.get("/")
    def get_products(user: User = Depends(security.authenticated_user_or_401)):
        return []

    with aioresponses() as mock:
        mock.get(dummy_jwks_uri, payload=dummy_jwks_response_data)
        resp = client.get("/")
        assert resp.headers["WWW-Authenticate"] == "Bearer"


@skipif_oauth2_dependency_not_installed
def test_that_headers_are_returned_for_oauth2_and_basic_auth(app, client):
    security = FastAPISecurity()
    security.init_basic_auth([{"username": "user", "password": "pass"}])
    security.init_oauth2_through_jwks(dummy_jwks_uri, audiences=[dummy_audience])

    @app.get("/")
    def get_products(user: User = Depends(security.authenticated_user_or_401)):
        return []

    with aioresponses() as mock:
        mock.get(dummy_jwks_uri, payload=dummy_jwks_response_data)
        resp = client.get("/")
        # NOTE: They are actually set as separate headers
        assert resp.headers["WWW-Authenticate"] == "Basic, Bearer"
