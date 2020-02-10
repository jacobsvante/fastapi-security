import logging
from typing import Callable, Dict, List, Optional, Tuple

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPBasicCredentials
from fastapi.security.http import HTTPAuthorizationCredentials

from . import registry
from .basic import BasicAuthValidator
from .entities import AuthMethod, User, UserAuth, UserInfo
from .exceptions import AuthNotConfigured
from .oauth2 import Oauth2JwtAccessTokenValidator
from .oidc import OpenIdConnectDiscovery
from .permissions import UserPermission
from .schemes import http_basic_scheme, jwt_bearer_scheme

logger = logging.getLogger(__name__)

__all__ = ("FastAPISecurity",)


class FastAPISecurity:
    """FastAPI Security main class, to be instantiated by users of the package

    Must be initialized after object creation via the `init()` method.
    """

    def __init__(self):
        self.basic_auth = BasicAuthValidator()
        self.oauth2_jwt = Oauth2JwtAccessTokenValidator()
        self.oidc_discovery = OpenIdConnectDiscovery()
        self._permission_overrides = None

    def init(
        self,
        app: FastAPI,
        basic_auth_credentials: List[HTTPBasicCredentials] = None,
        permission_overrides: Dict[str, List[str]] = None,
        jwks_url: str = None,
        audiences: List[str] = None,
        oidc_discovery_url: str = None,
    ):
        self._permission_overrides = permission_overrides

        if basic_auth_credentials:
            # Initialize basic auth (superusers with all permissions)
            self.basic_auth.init(basic_auth_credentials)

        if jwks_url:
            # # Initialize OAuth 2.0 - user permissions are required for all flows
            # # except Client Credentials
            self.oauth2_jwt.init(jwks_url, audiences=audiences or [])

        if oidc_discovery_url and self.oauth2_jwt.is_configured():
            self.oidc_discovery.init(oidc_discovery_url)

    @property
    def user(self) -> Callable:
        """Dependency that returns User object, authenticated or not"""

        async def dependency(user_auth: UserAuth = Depends(self._user_auth)):
            return User(auth=user_auth)

        return dependency

    @property
    def authenticated_user_or_401(self) -> Callable:
        """Dependency that returns User object if authenticated,
        otherwise raises HTTP401
        """

        async def dependency(user_auth: UserAuth = Depends(self._user_auth_or_401)):
            return User(auth=user_auth)

        return dependency

    @property
    def user_with_info(self) -> Callable:
        """Dependency that returns User object with user info, authenticated or not"""

        async def dependency(user_auth: UserAuth = Depends(self._user_auth)):
            if user_auth.is_oauth2():
                info = await self.oidc_discovery.get_user_info(user_auth.access_token)
            else:
                info = UserInfo.make_dummy()
            return User(auth=user_auth, info=info)

        return dependency

    @property
    def authenticated_user_with_info_or_401(self) -> Callable:
        """Dependency that returns User object along with user info if authenticated,
        otherwise raises HTTP401
        """

        async def dependency(user_auth: UserAuth = Depends(self._user_auth_or_401)):
            if user_auth.is_oauth2():
                info = await self.oidc_discovery.get_user_info(user_auth.access_token)
            else:
                info = UserInfo.make_dummy()
            return User(auth=user_auth, info=info)

        return dependency

    def has_permission(self, permission: UserPermission) -> Callable:
        """Dependency that raises HTTP403 if the user is missing the given permission
        """

        async def dependency(
            user: User = Depends(self.authenticated_user_or_401),
        ) -> User:
            self._has_permission_or_raise_forbidden(user, permission)
            return user

        return dependency

    def user_with_permissions(
        self, *permissions: Tuple[UserPermission, ...]
    ) -> Callable:
        """Dependency that returns the user if it has the given permissions, otherwise
        raises HTTP403
        """

        async def dependency(
            user: User = Depends(self.authenticated_user_or_401),
        ) -> User:
            for perm in permissions:
                self._has_permission_or_raise_forbidden(user, perm)
            return user

        return dependency

    @property
    def _user_auth(self) -> Callable:
        """Dependency that returns UserAuth object if authentication was successful"""

        async def dependency(
            bearer_credentials: HTTPAuthorizationCredentials = Depends(
                jwt_bearer_scheme
            ),
            http_credentials: HTTPAuthorizationCredentials = Depends(http_basic_scheme),
        ) -> Optional[UserAuth]:
            if not any(
                [self.oauth2_jwt.is_configured(), self.basic_auth.is_configured()]
            ):

                raise AuthNotConfigured()

            if bearer_credentials is not None:
                bearer_token = bearer_credentials.credentials
                access_token = await self.oauth2_jwt.parse(bearer_token)
                if access_token:
                    return self._maybe_override_permissions(
                        UserAuth.from_jwt_access_token(access_token)
                    )
            elif http_credentials is not None and self.basic_auth.is_configured():
                if self.basic_auth.validate(http_credentials):
                    return self._maybe_override_permissions(
                        UserAuth(
                            subject=http_credentials.username,
                            auth_method=AuthMethod.basic_auth,
                        )
                    )

            return UserAuth.make_anonymous()

        return dependency

    @property
    def _user_auth_or_401(self) -> Callable:
        """Dependency that returns UserAuth object on success, or raises HTTP401"""

        async def dependency(
            user_auth: UserAuth = Depends(self._user_auth),
            http_credentials: HTTPAuthorizationCredentials = Depends(http_basic_scheme),
        ):

            if user_auth and user_auth.is_authenticated():
                return user_auth

            if self.basic_auth.is_configured() and http_credentials is not None:
                www_authenticate_header_val = "Basic"
            else:
                www_authenticate_header_val = "Bearer"

            raise HTTPException(
                status_code=401,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": www_authenticate_header_val},
            )

        return dependency

    def _has_permission_or_raise_forbidden(self, user: User, perm: UserPermission):
        if not user.has_permission(perm.identifier):
            self._raise_forbidden(perm.identifier)

    def _raise_forbidden(self, required_permission: str):
        raise HTTPException(
            403, detail=f"Missing required permission {required_permission}",
        )

    def _maybe_override_permissions(self, user_auth: UserAuth) -> UserAuth:
        overrides = (self._permission_overrides or {}).get(user_auth.subject)

        if overrides is None:
            return user_auth

        all_permissions = registry.get_all_permissions()

        if "*" in overrides:
            return user_auth.with_permissions(all_permissions)
        else:
            return user_auth.with_permissions(
                [p for p in overrides if p in all_permissions]
            )
