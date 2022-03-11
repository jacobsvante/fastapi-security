__all__ = (
    "OAUTH2_DEPENDENCY_INSTALLED",
    "_RSAPublicKey",
    "RSAAlgorithm",
    "aiohttp",
    "jwt",
)

try:
    import aiohttp
except ImportError:

    class aiohttp:  # type: ignore[no-redef]
        pass


try:
    import jwt
    from jwt.algorithms import RSAAlgorithm
except ImportError:
    OAUTH2_DEPENDENCY_INSTALLED = False

    class jwt:  # type: ignore[no-redef]
        pass

    class RSAAlgorithm:  # type: ignore[no-redef]
        pass

else:
    OAUTH2_DEPENDENCY_INSTALLED = True


try:
    from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
except ImportError:

    class _RSAPublicKey:  # type: ignore[no-redef]
        pass
