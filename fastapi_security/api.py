import logging
from typing import Callable, Dict, Iterable, List, Optional, Type

from fastapi import Depends, HTTPException
from fastapi.security.http import HTTPAuthorizationCredentials
from starlette.datastructures import Headers

from .basic import BasicAuthValidator, IterableOfHTTPBasicCredentials
from .entities import AuthMethod, User, UserAuth, UserInfo
from .exceptions import AuthNotConfigured
from .oauth2 import Oauth2JwtAccessTokenValidator
from .oidc import OpenIdConnectDiscovery
from .permissions import PermissionOverrides, UserPermission
from .schemes import http_basic_scheme, jwt_bearer_scheme

logger = logging.getLogger(__name__)

__all__ = ("FastAPISecurity",)


class FastAPISecurity:
    """FastAPI Security main class, to be instantiated by users of the package

    Must be initialized after object creation via the `init()` method.
    """

    def __init__(self, *, user_permission_class: Type[UserPermission] = UserPermission):
        self.basic_auth = BasicAuthValidator()
        self.oauth2_jwt = Oauth2JwtAccessTokenValidator()
        self.oidc_discovery = OpenIdConnectDiscovery()
        self._permission_overrides: Dict[str, List[str]] = {}
        self._user_permission_class = user_permission_class
        self._all_permissions: List[UserPermission] = []
        self._oauth2_init_through_oidc = False
        self._oauth2_audiences: List[str] = []

    def init_basic_auth(self, basic_auth_credentials: IterableOfHTTPBasicCredentials):
        self.basic_auth.init(basic_auth_credentials)

    def init_oauth2_through_oidc(
        self, oidc_discovery_url: str, *, audiences: Iterable[str] = None
    ):
        """Initialize OIDC and OAuth2 authentication/authorization

        OAuth2 JWKS URL is lazily fetched from the OIDC endpoint once it's needed for the first time.

        This method is preferred over `init_oauth2_through_jwks` as you get all the
        benefits of OIDC, with less configuration supplied.
        """
        self._oauth2_audiences.extend(audiences or [])
        self.oidc_discovery.init(oidc_discovery_url)

    def init_oauth2_through_jwks(
        self, jwks_uri: str, *, audiences: Iterable[str] = None
    ):
        """Initialize OAuth2

        It's recommended to use `init_oauth2_through_oidc` instead.
        """
        self._oauth2_audiences.extend(audiences or [])
        self.oauth2_jwt.init(jwks_uri, audiences=self._oauth2_audiences)

    def add_permission_overrides(self, overrides: PermissionOverrides):
        """Add wildcard or specific permissions to basic auth and/or OAuth2 users

        Example:
            security = FastAPISecurity()
            create_product = security.user_permission("products:create")

            # Give all permissions to the user johndoe
            security.add_permission_overrides({"johndoe": "*"})

            # Give the OAuth2 user `7ZmI5ycgNHeZ9fHPZZwTNbIRd9Ectxca@clients` the
            # "products:create" permission.
            security.add_permission_overrides({
                "7ZmI5ycgNHeZ9fHPZZwTNbIRd9Ectxca@clients": ["products:create"],
            })

        """
        for user, val in overrides.items():
            lst: List[str] = self._permission_overrides.setdefault(user, [])
            if isinstance(val, str):
                assert (
                    val == "*"
                ), "Only `*` is accepted as permission override when specified as a string"
                logger.debug(f"Adding wildcard `*` permission to user {user}")
                lst.append("*")
            else:
                for p in val:
                    logger.debug(f"Adding permission {p} to user {user}")
                    lst.append(p)

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
            if user_auth.is_oauth2() and user_auth.access_token:
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
            if user_auth.is_oauth2() and user_auth.access_token:
                info = await self.oidc_discovery.get_user_info(user_auth.access_token)
            else:
                info = UserInfo.make_dummy()
            return User(auth=user_auth, info=info)

        return dependency

    def user_permission(self, identifier: str) -> UserPermission:
        perm = self._user_permission_class(identifier)
        self._all_permissions.append(perm)
        return perm

    def user_holding(self, *permissions: UserPermission) -> Callable:
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
            oidc_configured = self.oidc_discovery.is_configured()
            oauth2_configured = self.oauth2_jwt.is_configured()
            basic_auth_configured = self.basic_auth.is_configured()

            if not any([oidc_configured, oauth2_configured, basic_auth_configured]):
                raise AuthNotConfigured()

            if oidc_configured and not oauth2_configured:
                jwks_uri = await self.oidc_discovery.get_jwks_uri()
                self.init_oauth2_through_jwks(jwks_uri)

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

            options = []

            if self.basic_auth.is_configured():
                options.append("Basic")
            if self.oauth2_jwt.is_configured():
                options.append("Bearer")

            raise HTTPException(
                status_code=401,
                detail="Could not validate credentials",
                headers=Headers(  # type: ignore[arg-type]
                    raw=[(b"WWW-Authenticate", o.encode("latin-1")) for o in options],
                ),
            )

        return dependency

    def _has_permission_or_raise_forbidden(self, user: User, perm: UserPermission):
        if not user.has_permission(perm.identifier):
            self._raise_forbidden(perm.identifier)

    def _raise_forbidden(self, required_permission: str):
        raise HTTPException(
            403,
            detail=f"Missing required permission {required_permission}",
        )

    def _maybe_override_permissions(self, user_auth: UserAuth) -> UserAuth:
        overrides = self._permission_overrides.get(user_auth.subject)

        all_permission_identifiers = [p.identifier for p in self._all_permissions]

        if overrides is None:
            return user_auth.with_permissions(
                [
                    incoming_id
                    for incoming_id in user_auth.permissions
                    if incoming_id in all_permission_identifiers
                ]
            )
        elif "*" in overrides:
            return user_auth.with_permissions(all_permission_identifiers)
        else:
            return user_auth.with_permissions(
                [p for p in overrides if p in all_permission_identifiers]
            )
