from typing import Dict, MutableSequence, Union

__all__ = ("PermissionOverrides",)


PermissionOverrides = Dict[str, Union[str, MutableSequence[str]]]


class UserPermission:
    """Represents a user permission

    Creating a new permission is done like this:

        security = FastAPISecurity()
        create_item_permission = security.user_permission("item:create")

    Usage:

        @app.post(
            "/products",
            dependencies=[Depends(security.user_holding(create_item_permission))]
        )
        def create_product(...):
            ...

    Or:
        @app.post("/products")
        def create_product(
            user: Depends(security.user_holding(create_item_permission))
        ):
            ...

    """

    def __init__(self, identifier: str):
        self.identifier = identifier

    def __str__(self):
        return self.identifier

    def __repr__(self):
        return f"{self.__class__.__name__}({self.identifier})"
