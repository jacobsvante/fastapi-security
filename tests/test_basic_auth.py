from fastapi import Depends

from fastapi_security import FastAPISecurity, User


def test_that_basic_auth_rejects_incorrect_credentials(app, client):
    security = FastAPISecurity()

    @app.get("/")
    def get_products(user: User = Depends(security.authenticated_user_or_401)):
        return []

    credentials = [{"username": "user", "password": "pass"}]
    security.init(app, basic_auth_credentials=credentials)

    resp = client.get("/")
    assert resp.status_code == 401

    resp = client.get("/", auth=("user", ""))
    assert resp.status_code == 401

    resp = client.get("/", auth=("", "pass"))
    assert resp.status_code == 401


def test_that_basic_auth_accepts_correct_credentials(app, client):
    security = FastAPISecurity()

    @app.get("/")
    def get_products(user: User = Depends(security.authenticated_user_or_401)):
        return []

    credentials = [{"username": "user", "password": "pass"}]
    security.init(app, basic_auth_credentials=credentials)

    resp = client.get("/", auth=("user", "pass"))
    assert resp.status_code == 200
