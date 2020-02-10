from datetime import datetime
from enum import Enum
from typing import Any, Dict, List

from pydantic import BaseModel, Field, root_validator, validator

from . import registry

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
    _extra: Dict[str, Any] = Field(
        {}, description="Any extra fields that were provided in the access token"
    )

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

    @root_validator(pre=True)
    def set_extra_field(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure that any additional passed in data is set on the `extra` field"""
        extra = {}
        new_values = {"_extra": extra}
        model_keys = cls.__fields__.keys()

        for k, v in values.items():
            if k in model_keys:
                new_values[k] = v
            else:
                extra[k] = v

        return new_values


class AuthMethod(str, Enum):
    none = "none"
    basic_auth = "basic_auth"
    oauth2 = "oauth2"
    oauth2_client_credentials = "oauth2_client_credentials"

    def is_oauth2_type(self):
        return self in (AuthMethod.oauth2_client_credentials, AuthMethod.oauth2)


class UserInfo(BaseModel):
    given_name: str = None
    family_name: str = None
    nickname: str = None
    name: str = None
    picture: str = None
    locale: str = None
    updated_at: datetime = None
    email: str = None
    email_verified: bool = None

    @classmethod
    def from_oidc_endpoint(cls, data: Dict[str, Any]) -> "UserInfo":
        return cls(**data)

    @classmethod
    def make_dummy(cls):
        return cls()


class UserAuth(BaseModel):
    subject: str
    auth_method: AuthMethod
    issuer: str = None
    audience: List[str] = []
    issued_at: datetime = None
    expires_at: datetime = None
    scopes: List[str] = []
    permissions: List[str] = []
    access_token: str = None
    _extra: Dict[str, Any] = {}

    @validator("permissions", pre=True, always=True)
    def only_add_valid_permissions(cls, v, values):
        if v:
            all_permissions = registry.get_all_permissions()
            return [e for e in v if e in all_permissions]
        else:
            return v

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
            _extra=access_token._extra,
        )

    @classmethod
    def make_anonymous(cls) -> "UserAuth":
        return cls(subject="anonymous", auth_method=AuthMethod.none)


class User(BaseModel):
    auth: UserAuth
    info: UserInfo = None

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

    def without_extra(self) -> "User":
        return self.copy(deep=True, exclude={"auth": {"extra"}})
