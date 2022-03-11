# Changelog

## [0.3.1](https://github.com/jmagnusson/fastapi-security/compare/v0.3.0...v0.3.1) (2021-03-29)


### Bug Fixes

- Handle permission overrides iterators that are exhaustable
- Ensure that a string permission override is always equal to `*`

## [0.3.0](https://github.com/jmagnusson/fastapi-security/compare/v0.2.0...v0.3.0) (2021-03-26)


### Features

- OAuth2 and OIDC can now be enabled by just passing an OIDC discovery URL to `FastAPISecurity.init_oauth2_through_oidc`
- Cached data is now used for JWKS and OIDC endpoints in case the "refresh requests" fail.
- `UserPermission` objects are now created via `FastAPISecurity.user_permission`.
- `FastAPISecurity.init` was split into three distinct methods: `.init_basic_auth`, `.init_oauth2_through_oidc` and `.init_oauth2_through_jwks`.
- Broke out the `permission_overrides` argument from the old `.init` method and added a distinct method for adding new overrides `add_permission_overrides`. This method can be called multiple times.
- The dependency `FastAPISecurity.has_permission` and `FastAPISecurity.user_with_permissions` has been replaced by `FastAPISecurity.user_holding`. API is the same (takes a variable number of UserPermission arguments, i.e. compatible with both).
- Remove `app` argument to the `FastAPISecurity.init...` methods (it wasn't used before)
- The global permissions registry has been removed. Now there should be no global mutable state left.
