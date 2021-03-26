import datetime

from fastapi_security.entities import (
    AuthMethod,
    JwtAccessToken,
    User,
    UserAuth,
    UserInfo,
)


def test_make_dummy_user_info():
    dummy = UserInfo.make_dummy()
    assert dummy.dict() == {
        "given_name": None,
        "family_name": None,
        "nickname": None,
        "name": None,
        "picture": None,
        "locale": None,
        "updated_at": None,
        "email": None,
        "email_verified": None,
    }


def test_anonymous_user_auth():
    anon = UserAuth.make_anonymous()
    assert anon.is_anonymous()
    assert anon.dict() == {
        "subject": "anonymous",
        "auth_method": AuthMethod.none,
        "issuer": None,
        "audience": [],
        "issued_at": None,
        "expires_at": None,
        "scopes": [],
        "permissions": [],
        "access_token": None,
    }


def test_user_auth_get_user_id():
    u = UserAuth(subject="johndoe", auth_method="basic_auth")
    assert u.get_user_id() == "johndoe"


def test_that_user_auth_accepts_client_credentials_grant_type():
    jwt_token = JwtAccessToken(
        iss="a",
        sub="johndoe",
        aud="a",
        iat="2021-03-26 11:25",
        exp="2021-03-27 11:25",
        raw="",
        gty="client-credentials",
    )
    assert jwt_token.is_client_credentials()

    auth = UserAuth.from_jwt_access_token(jwt_token)
    assert auth.is_oauth2()


def test_that_user_methods_work_correctly():
    jwt_token = JwtAccessToken(
        iss="a",
        sub="johndoe",
        aud="a",
        iat="2021-03-26 11:25",
        exp="2021-03-27 11:25",
        raw="",
        permissions=["products:create"],
    )
    auth = UserAuth.from_jwt_access_token(jwt_token)
    user = User(auth=auth)
    assert user.permissions == ["products:create"]
    # NOTE: Expiry etc is validated in a higher layer
    assert user.is_authenticated()
    assert not user.is_anonymous()
    assert user.get_user_id() == "johndoe"
    assert user.has_permission("products:create")

    assert user.dict()["auth"] == {
        "access_token": "",
        "audience": ["a"],
        "auth_method": AuthMethod.oauth2,
        "expires_at": datetime.datetime(2021, 3, 27, 11, 25),
        "issued_at": datetime.datetime(2021, 3, 26, 11, 25),
        "issuer": "a",
        "permissions": ["products:create"],
        "scopes": [],
        "subject": "johndoe",
    }
