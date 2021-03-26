from fastapi import Depends

from fastapi_security import FastAPISecurity, HTTPBasicCredentials, User


def test_that_explicit_permission_overrides_are_applied(app, client):
    cred = HTTPBasicCredentials(username="johndoe", password="123")

    security = FastAPISecurity()

    create_product_perm = security.user_permission("products:create")

    security.init_basic_auth([cred])
    security.add_permission_overrides({"johndoe": ["products:create"]})

    @app.post("/products")
    def create_product(
        user: User = Depends(security.user_holding(create_product_perm)),
    ):
        return {"ok": True}

    resp = client.post("/products", auth=("johndoe", "123"))

    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_that_wildcard_permission_overrides_are_applied(app, client):
    cred = HTTPBasicCredentials(username="johndoe", password="123")

    security = FastAPISecurity()

    create_product_perm = security.user_permission("products:create")

    security.init_basic_auth([cred])
    security.add_permission_overrides({"johndoe": "*"})

    @app.post("/products")
    def create_product(
        user: User = Depends(security.user_holding(create_product_perm)),
    ):
        return {"ok": True}

    resp = client.post("/products", auth=("johndoe", "123"))

    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
