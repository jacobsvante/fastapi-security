from typing import List

__all__ = ()


_permissions_registry: List[str] = []


def add_permission(permission: str):
    if permission not in _permissions_registry:
        _permissions_registry.append(permission)


def get_all_permissions() -> List[str]:
    return _permissions_registry.copy()
