from pathlib import Path

import pytest
import requests

from .helpers import run_example_app

try:
    import uvicorn
except ImportError:
    uvicorn = None

app1_path = Path("./examples/app1")

pytestmark = [
    pytest.mark.skipif(not app1_path.exists(), reason="app1 example couldn't be found"),
    pytest.mark.skipif(uvicorn is None, reason="`uvicorn` isn't installed"),
    pytest.mark.slow,
]


basic_auth_env = {
    "BASIC_AUTH_CREDENTIALS": '[{"username": "user1", "password": "test"}]'
}


def test_users_me_basic_auth_anonymous():
    with run_example_app("examples.app1:app", env=basic_auth_env) as base_url:
        resp = requests.get(f"{base_url}/users/me")
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth"] == {
            "subject": "anonymous",
            "auth_method": "none",
            "issuer": None,
            "audience": [],
            "issued_at": None,
            "expires_at": None,
            "scopes": [],
            "permissions": [],
        }


def test_users_me_basic_auth_authenticated():
    with run_example_app("examples.app1:app", env=basic_auth_env) as base_url:
        resp = requests.get(f"{base_url}/users/me", auth=("user1", "test"))
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth"] == {
            "subject": "user1",
            "auth_method": "basic_auth",
            "issuer": None,
            "audience": [],
            "issued_at": None,
            "expires_at": None,
            "scopes": [],
            "permissions": [],
        }


def test_user_permissions_basic_auth_authenticated():
    with run_example_app(
        "examples.app1:app",
        env={**basic_auth_env, "PERMISSION_OVERRIDES": '{"user1": ["*"]}'},
    ) as base_url:
        resp = requests.get(f"{base_url}/users/me/permissions", auth=("user1", "test"))
        assert resp.status_code == 200
        data = resp.json()
        assert data == ["products:create"]


def test_create_product_unauthenticated():
    with run_example_app("examples.app1:app", env=basic_auth_env) as base_url:
        resp = requests.post(f"{base_url}/products")
        assert resp.status_code == 401
        data = resp.json()
        assert data == {"detail": "Could not validate credentials"}


def test_create_product_authenticated():
    with run_example_app(
        "examples.app1:app",
        env={**basic_auth_env, "PERMISSION_OVERRIDES": '{"user1": ["*"]}'},
    ) as base_url:
        resp = requests.post(
            f"{base_url}/products", auth=("user1", "test"), json={"name": "T-shirt"}
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data == {"name": "T-shirt"}
