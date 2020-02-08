from typing import Tuple

from fastapi import Depends, HTTPException

from . import registry
from .dependencies import get_authenticated_user_or_401
from .entities import User

__all__ = ("UserPermission", "UserWithPermissions")


class UserPermission:
    """FastAPI dependency that raises 403 if the user is missing the given permission

    This class is meant to be subclassed. Example:

        create_item_permission = UserPermission("item:create")

    Usage:

        @app.post("/products", dependencies=[Depends(create_item_permission)])
        def create_product(...):
            ...

    """

    def __init__(self, identifier: str):
        self.identifier = identifier
        registry.add_permission(identifier)

    def __call__(self, user: User = Depends(get_authenticated_user_or_401)):
        self.has_permission_or_raise_forbidden(user)

    def __str__(self):
        return self.identifier

    def __repr__(self):
        return f"<UserPermission: {self.identifier}>"

    def has_permission_or_raise_forbidden(self, user: User):
        if not user.has_permission(self.identifier):
            self._raise_forbidden(self.identifier)

    def _raise_forbidden(self, required_permission: str):
        raise HTTPException(
            403, detail=f"Missing required permission {required_permission}",
        )


class UserWithPermissions:
    """FastAPI dependency that returns User object if it's authenticated and has the given permissions

    Raises HTTP 401 if the user is not authenticated and HTTP 403 if the user is
    missing any of the given permissions.
    """

    def __init__(self, *permissions: Tuple[UserPermission, ...]):
        self._permissions = permissions

    def __call__(self, user: User = Depends(get_authenticated_user_or_401)) -> User:
        for perm in self._permissions:
            perm.has_permission_or_raise_forbidden(user)
        return user
