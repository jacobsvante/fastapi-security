__all__ = ("AuthNotConfigured",)


class AuthNotConfigured(Exception):
    """Raised when no authentication backend has been set up"""
