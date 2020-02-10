from . import registry

__all__ = ("UserPermission",)


class UserPermission:
    """Represents a user permission

    Creating a new permission is done like this:

        create_item_permission = UserPermission("item:create")

    Usage:

        @app.post(
            "/products",
            dependencies=[Depends(security.has_permission(create_item_permission))]
        )
        def create_product(...):
            ...

    Or:
        @app.post("/products")
        def create_product(
            user: Depends(security.user_with_permissions(create_item_permission))
        ):
            ...

    """

    def __init__(self, identifier: str):
        self.identifier = identifier
        registry.add_permission(identifier)

    def __str__(self):
        return self.identifier

    def __repr__(self):
        return f"<UserPermission: {self.identifier}>"
