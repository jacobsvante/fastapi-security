import logging
from typing import List

from fastapi import Depends, FastAPI

from fastapi_security import FastAPISecurity, User

from . import db
from .models import Product
from .settings import get_settings

app = FastAPI()

settings = get_settings()

security = FastAPISecurity()

if settings.basic_auth_credentials:
    security.init_basic_auth(settings.basic_auth_credentials)

if settings.oidc_discovery_url:
    security.init_oauth2_through_oidc(
        settings.oidc_discovery_url,
        audiences=settings.oauth2_audiences,
    )
elif settings.oauth2_jwks_url:
    security.init_oauth2_through_jwks(
        settings.oauth2_jwks_url,
        audiences=settings.oauth2_audiences,
    )

security.add_permission_overrides(settings.permission_overrides or {})


logger = logging.getLogger(__name__)

create_product_perm = security.user_permission("products:create")


@app.get("/users/me")
async def get_user_details(user: User = Depends(security.user_with_info)):
    """Return user details, regardless of whether user is authenticated or not"""
    return user.without_access_token()


@app.get("/users/me/permissions", response_model=List[str])
def get_user_permissions(user: User = Depends(security.authenticated_user_or_401)):
    """Return user permissions or HTTP401 if not authenticated"""
    return user.permissions


@app.post("/products", response_model=Product, status_code=201)
async def create_product(
    product: Product,
    user: User = Depends(security.user_holding(create_product_perm)),
):
    """Create product

    Requires the authenticated user to have the `products:create` permission
    """
    await db.persist(product)
    return product
