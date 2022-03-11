from aioresponses import aioresponses
from fastapi import Depends

from fastapi_security import FastAPISecurity, User
from fastapi_security.permissions import UserPermission

from ..helpers.jwks import (
    dummy_audience,
    dummy_jwks_response_data,
    dummy_jwks_uri,
    make_access_token,
    skipif_oauth2_dependency_not_installed,
)


def test_user_permission_repr():
    perm = UserPermission("inventory:list")
    assert repr(perm) == "UserPermission(inventory:list)"


def test_user_permission_str():
    perm = UserPermission("inventory:list")
    assert str(perm) == "inventory:list"


@skipif_oauth2_dependency_not_installed
def test_that_missing_permission_results_in_403(app, client):

    security = FastAPISecurity()

    can_list = security.user_permission("users:list")  # noqa

    @app.get("/users")
    def get_user_list(user: User = Depends(security.user_holding(can_list))):
        return [user]

    security.init_oauth2_through_jwks(dummy_jwks_uri, audiences=[dummy_audience])

    access_token = make_access_token(sub="test-user", permissions=[])

    with aioresponses() as mock:
        mock.get(dummy_jwks_uri, payload=dummy_jwks_response_data)

        resp = client.get("/users", headers={"Authorization": f"Bearer {access_token}"})
        assert resp.status_code == 403
        assert resp.json() == {"detail": "Missing required permission users:list"}


@skipif_oauth2_dependency_not_installed
def test_that_assigned_permission_result_in_200(app, client):

    security = FastAPISecurity()

    can_list = security.user_permission("users:list")  # noqa

    @app.get("/users")
    def get_user_list(user: User = Depends(security.user_holding(can_list))):
        return [user]

    security.init_oauth2_through_jwks(dummy_jwks_uri, audiences=[dummy_audience])

    access_token = make_access_token(sub="test-user", permissions=["users:list"])

    with aioresponses() as mock:
        mock.get(dummy_jwks_uri, payload=dummy_jwks_response_data)

        resp = client.get("/users", headers={"Authorization": f"Bearer {access_token}"})
        assert resp.status_code == 200
        (user1,) = resp.json()
        assert user1["auth"]["subject"] == "test-user"


@skipif_oauth2_dependency_not_installed
def test_that_user_must_have_all_permissions(app, client):

    security = FastAPISecurity()

    can_list = security.user_permission("users:list")  # noqa
    can_view = security.user_permission("users:view")  # noqa

    @app.get("/users")
    def get_user_list(user: User = Depends(security.user_holding(can_list, can_view))):
        return [user]

    security.init_oauth2_through_jwks(dummy_jwks_uri, audiences=[dummy_audience])

    bad_token = make_access_token(sub="test-user", permissions=["users:list"])
    valid_token = make_access_token(
        sub="JaneDoe",
        permissions=["users:list", "users:view"],
    )

    with aioresponses() as mock:
        mock.get(dummy_jwks_uri, payload=dummy_jwks_response_data)

        resp = client.get("/users", headers={"Authorization": f"Bearer {bad_token}"})
        assert resp.status_code == 403
        assert resp.json() == {"detail": "Missing required permission users:view"}

        resp = client.get("/users", headers={"Authorization": f"Bearer {valid_token}"})
        assert resp.status_code == 200
        (user1,) = resp.json()
        assert user1["auth"]["subject"] == "JaneDoe"
