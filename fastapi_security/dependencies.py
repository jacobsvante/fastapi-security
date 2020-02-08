from typing import Optional

from fastapi import Depends, HTTPException
from fastapi.security.http import HTTPAuthorizationCredentials

from .basic import basic_auth
from .entities import AuthMethod, User, UserAuth, UserInfo
from .jwt import oauth2_jwt
from .oidc import oidc_discovery
from .schemes import http_basic_scheme, jwt_bearer_scheme

__all__ = (
    "get_user_auth",
    "get_user_auth_or_401",
    "get_user",
    "get_authenticated_user_or_401",
    "get_user_with_info",
    "get_authenticated_user_with_info_or_401",
)


async def get_user_auth(
    bearer_credentials: HTTPAuthorizationCredentials = Depends(jwt_bearer_scheme),
    http_credentials: HTTPAuthorizationCredentials = Depends(http_basic_scheme),
) -> Optional[UserAuth]:
    """Dependency that returns UserAuth object if authentication was successful"""
    if not any([oauth2_jwt.is_configured(), basic_auth.is_configured()]):
        raise RuntimeError(
            "Auth dependency used, but no auth backend has been configured"
        )

    if bearer_credentials is not None:
        bearer_token = bearer_credentials.credentials
        access_token = await oauth2_jwt.parse(bearer_token)
        if access_token:
            return UserAuth.from_jwt_access_token(access_token)
    elif http_credentials is not None and basic_auth.is_configured():
        if basic_auth.validate(http_credentials):
            return UserAuth(
                subject=http_credentials.username, auth_method=AuthMethod.basic_auth
            )

    return UserAuth.make_anonymous()


async def get_user_auth_or_401(
    user_auth: UserAuth = Depends(get_user_auth),
    http_credentials: HTTPAuthorizationCredentials = Depends(http_basic_scheme),
) -> UserAuth:
    """Dependency that returns UserAuth object on success, or raises HTTP401"""

    if user_auth and user_auth.is_authenticated():
        return user_auth

    if basic_auth.is_configured() and http_credentials is not None:
        www_authenticate_header_val = "Basic"
    else:
        www_authenticate_header_val = "Bearer"

    raise HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": www_authenticate_header_val},
    )


async def get_user(user_auth: UserAuth = Depends(get_user_auth),) -> User:
    """Dependency that returns User object, authenticated or not"""
    return User(auth=user_auth)


async def get_authenticated_user_or_401(
    user_auth: UserAuth = Depends(get_user_auth_or_401),
) -> User:
    """Dependency that returns User object if authenticated, otherwise raises HTTP401"""
    return User(auth=user_auth)


async def get_user_with_info(user_auth: UserAuth = Depends(get_user_auth),) -> User:
    """Dependency that returns User object with user info, authenticated or not"""
    if user_auth.is_oauth2():
        info = await oidc_discovery.get_user_info(user_auth.access_token)
    else:
        info = UserInfo.make_dummy()
    return User(auth=user_auth, info=info)


async def get_authenticated_user_with_info_or_401(
    user_auth: UserAuth = Depends(get_user_auth_or_401),
) -> User:
    """Dependency that returns User object along with user info if authenticated,
    otherwise raises HTTP401
    """
    if user_auth.is_oauth2():
        info = await oidc_discovery.get_user_info(user_auth.access_token)
    else:
        info = UserInfo.make_dummy()
    return User(auth=user_auth, info=info)
