from fastapi.security.http import HTTPBasic, HTTPBearer

__all__ = ()

jwt_bearer_scheme = HTTPBearer(
    auto_error=False,
    bearerFormat="JWT-formatted OAuth2 Access Token",
    scheme_name="JWT-formatted OAuth2 Access Token",
)
http_basic_scheme = HTTPBasic(auto_error=False)
