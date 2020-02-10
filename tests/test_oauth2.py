from aioresponses import aioresponses
from fastapi import Depends

from fastapi_security import FastAPISecurity, User

from .jwks_helpers import (
    dummy_audience,
    dummy_jwks_response_data,
    dummy_jwks_url,
    make_access_token,
)


def test_that_oauth2_rejects_incorrect_token(app, client):

    security = FastAPISecurity()

    @app.get("/")
    def get_products(user: User = Depends(security.authenticated_user_or_401)):
        return []

    security.init(app, jwks_url=dummy_jwks_url, audiences=[dummy_audience])

    resp = client.get("/")
    assert resp.status_code == 401

    resp = client.get("/", headers={"Authorization": "Bearer abc"})
    assert resp.status_code == 401

    resp = client.get("/", headers={"Authorization": "Bearer abc.xyz.def"})
    assert resp.status_code == 401


def test_that_oauth2_accepts_correct_token(app, client):

    security = FastAPISecurity()

    @app.get("/")
    def get_products(user: User = Depends(security.authenticated_user_or_401)):
        return []

    security.init(app, jwks_url=dummy_jwks_url, audiences=[dummy_audience])

    access_token = make_access_token(sub="test-subject")

    with aioresponses() as mock:
        mock.get(dummy_jwks_url, payload=dummy_jwks_response_data)

        resp = client.get("/", headers={"Authorization": f"Bearer {access_token}"})

        assert resp.status_code == 200


def test_that_oauth2_rejects_expired_token(app, client):

    security = FastAPISecurity()

    @app.get("/")
    def get_products(user: User = Depends(security.authenticated_user_or_401)):
        return []

    security.init(app, jwks_url=dummy_jwks_url, audiences=[dummy_audience])

    access_token = make_access_token(sub="test-subject", expire_in=-1)

    with aioresponses() as mock:
        mock.get(dummy_jwks_url, payload=dummy_jwks_response_data)

        resp = client.get("/", headers={"Authorization": f"Bearer {access_token}"})

        assert resp.status_code == 401
