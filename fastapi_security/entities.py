from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator

__all__ = ("User",)


class JwtAccessToken(BaseModel):
    iss: str = Field(..., description="Issuer")
    sub: str = Field(..., description="Subject")
    aud: List[str] = Field(..., description="Audience")
    iat: datetime = Field(..., description="Issued At")
    exp: datetime = Field(..., description="Expiration Time")
    azp: str = Field(
        None,
        description="Authorized party - the party to which the ID Token was issued",
    )
    gty: str = Field(
        "",
        description="Grant type (auth0 specific, see https://auth0.com/docs/applications/concepts/application-grant-types)",
    )
    scope: List[str] = Field("", description="Scope Values")
    permissions: List[str] = Field(
        [],
        description="Permissions (auth0 specific, intended for first-party app authorization)",
    )
    raw: str = Field(..., description="The raw access token")

    @validator("aud", pre=True, always=True)
    def aud_to_list(cls, v):
        return v.split(" ") if isinstance(v, str) else v

    @validator("scope", pre=True, always=True)
    def scope_to_list(cls, v):
        if isinstance(v, str):
            return [s for s in v.split(" ") if s]
        else:
            return v

    @validator("permissions", pre=True, always=True)
    def permissions_to_list(cls, v):
        return v.split(" ") if isinstance(v, str) else v

    def is_client_credentials(self):
        return self.gty == "client-credentials"


class AuthMethod(str, Enum):
    none = "none"
    basic_auth = "basic_auth"
    oauth2 = "oauth2"
    oauth2_client_credentials = "oauth2_client_credentials"

    def is_oauth2_type(self):
        return self in (AuthMethod.oauth2_client_credentials, AuthMethod.oauth2)


class UserInfo(BaseModel):
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    nickname: Optional[str] = None
    name: Optional[str] = None
    picture: Optional[str] = None
    locale: Optional[str] = None
    updated_at: Optional[datetime] = None
    email: Optional[str] = None
    email_verified: Optional[bool] = None

    @classmethod
    def from_oidc_endpoint(cls, data: Dict[str, Any]) -> "UserInfo":
        return cls(**data)

    @classmethod
    def make_dummy(cls):
        return cls()


class UserAuth(BaseModel):
    subject: str
    auth_method: AuthMethod
    issuer: Optional[str] = None
    audience: List[str] = []
    issued_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    scopes: List[str] = []
    permissions: List[str] = []
    access_token: Optional[str] = None

    def is_authenticated(self) -> bool:
        return self.auth_method is not AuthMethod.none

    def is_anonymous(self) -> bool:
        return not self.is_authenticated()

    def is_oauth2(self) -> bool:
        return self.auth_method.is_oauth2_type()

    def get_user_id(self) -> str:
        return self.subject

    def with_permissions(self, permissions: List[str]) -> "UserAuth":
        return self.copy(deep=True, update={"permissions": permissions})

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    @classmethod
    def from_jwt_access_token(cls, access_token: JwtAccessToken) -> "UserAuth":
        if access_token.is_client_credentials():
            auth_method = AuthMethod.oauth2_client_credentials
        else:
            auth_method = AuthMethod.oauth2
        return cls(
            auth_method=auth_method,
            subject=access_token.sub,
            issuer=access_token.iss,
            audience=access_token.aud,
            issued_at=access_token.iat,
            expires_at=access_token.exp,
            scopes=access_token.scope,
            permissions=access_token.permissions,
            access_token=access_token.raw,
        )

    @classmethod
    def make_anonymous(cls) -> "UserAuth":
        return cls(subject="anonymous", auth_method=AuthMethod.none)


class User(BaseModel):
    auth: UserAuth
    info: Optional[UserInfo] = None

    @property
    def permissions(self) -> List[str]:
        return self.auth.permissions

    def is_authenticated(self) -> bool:
        return self.auth.is_authenticated()

    def is_anonymous(self) -> bool:
        return self.auth.is_anonymous()

    def get_user_id(self) -> str:
        return self.auth.get_user_id()

    def has_permission(self, permission: str) -> bool:
        return self.auth.has_permission(permission)

    def without_access_token(self) -> "User":
        return self.copy(deep=True, exclude={"auth": {"access_token"}})
