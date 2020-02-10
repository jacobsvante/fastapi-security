from aioresponses import aioresponses
from fastapi import Depends

from fastapi_security import FastAPISecurity, User, UserPermission

from .jwks_helpers import (
    dummy_audience,
    dummy_jwks_response_data,
    dummy_jwks_url,
    make_access_token,
)


def test_that_missing_permission_results_in_403(app, client):

    security = FastAPISecurity()

    can_list = UserPermission("users:list")  # noqa

    @app.get("/users/registry")
    def get_user_list(user: User = Depends(security.user_with_permissions(can_list))):
        return [user]

    security.init(app, jwks_url=dummy_jwks_url, audiences=[dummy_audience])

    access_token = make_access_token(sub="test-user", permissions=[])

    with aioresponses() as mock:
        mock.get(dummy_jwks_url, payload=dummy_jwks_response_data)

        resp = client.get(
            "/users/registry", headers={"Authorization": f"Bearer {access_token}"}
        )
        assert resp.status_code == 403
        assert resp.json() == {"detail": "Missing required permission users:list"}


def test_that_assigned_permission_result_in_200(app, client):

    security = FastAPISecurity()

    can_list = UserPermission("users:list")  # noqa

    @app.get("/users/registry")
    def get_user_list(user: User = Depends(security.user_with_permissions(can_list))):
        return [user]

    security.init(app, jwks_url=dummy_jwks_url, audiences=[dummy_audience])

    access_token = make_access_token(sub="test-user", permissions=["users:list"])

    with aioresponses() as mock:
        mock.get(dummy_jwks_url, payload=dummy_jwks_response_data)

        resp = client.get(
            "/users/registry", headers={"Authorization": f"Bearer {access_token}"}
        )
        assert resp.status_code == 200
        (user1,) = resp.json()
        assert user1["auth"]["subject"] == "test-user"
