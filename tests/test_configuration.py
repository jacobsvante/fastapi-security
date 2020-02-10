import pytest
from fastapi import Depends

from fastapi_security import FastAPISecurity, User
from fastapi_security.exceptions import AuthNotConfigured


def test_that_endpoints_raise_exception_when_auth_is_unconfigured(app, client):
    security = FastAPISecurity()

    @app.get("/")
    def get_products(user: User = Depends(security.authenticated_user_or_401)):
        return []

    with pytest.raises(AuthNotConfigured):
        client.get("/")
