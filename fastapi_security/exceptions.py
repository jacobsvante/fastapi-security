__all__ = ("AuthNotConfigured", "MissingDependency")


class AuthNotConfigured(Exception):
    """Raised when no authentication backend has been set up"""


class MissingDependency(Exception):
    """Raised when a python dependency is missing that's needed"""
