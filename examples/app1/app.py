import logging
from typing import List

from fastapi import Depends, FastAPI

from fastapi_security import (
    User,
    UserPermission,
    UserWithPermissions,
    basic_auth,
    get_authenticated_user_or_401,
    get_user,
    get_user_with_info,
    oauth2_jwt,
    oidc_discovery
)

from . import db
from .models import Product
from .settings import get_settings

app = FastAPI()

logger = logging.getLogger(__name__)

create_product_perm = UserPermission("products:create")


@app.on_event("startup")
def enable_security():
    settings = get_settings()

    if settings.basic_auth_credentials:
        # Initialize basic auth (superusers with all permissions)
        basic_auth.init(settings.basic_auth_credentials)
    else:
        logger.warning("Basic Auth disabled - not configured in settings")
    if settings.auth_jwks_url and settings.auth_audiences:
        # # Initialize OAuth 2.0 - user permissions are required for all flows
        # # except Client Credentials
        oauth2_jwt.init(settings.auth_jwks_url, audiences=settings.auth_audiences)
    else:
        logger.warning("OAuth2 disabled - not configured in settings")
    if settings.oidc_discovery_url and oauth2_jwt.is_configured():
        oidc_discovery.init(settings.oidc_discovery_url)
    else:
        logger.info("OIDC Discovery disabled - not configured in settings")


@app.get("/users/me")
async def get_user_details(user: User = Depends(get_user_with_info)):
    """Return user details, regardless of whether user is authenticated or not"""
    return user.without_access_token()


@app.get("/users/me/permissions", response_model=List[str])
def get_user_permissions(user: User = Depends(get_authenticated_user_or_401),):
    """Return user permissions or HTTP401 if not authenticated"""
    return user.permissions


@app.post("/products", response_model=Product)
async def create_product(
    product: Product, user: User = Depends(UserWithPermissions(create_product_perm)),
):
    """Create product

    Requires the authenticated user to have the `products:create` permission
    """
    await db.persist(product)
    return product
