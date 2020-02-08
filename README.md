# FastAPI Security

Implements authentication and authorization as dependencies in FastAPI.

## Features

- Authentication via JWT-based OAuth 2 access tokens and Basic Auth
- Pydantic-based `User` model for authenticated and anonymous users
- Sub-classable `UserPermission` dependency to check against the `permissions` attribute returned in OAuth 2 access tokens

## Limitations

- Only supports validating access tokens using public keys from a JSON Web Key Set (JWKS) endpoint. I.e. for use with external identity providers such as Auth0 and ORY Hydra.
- Clients authenticating with Basic Auth and OAuth 2 *Client Credentials* are always granted all permissions (NOTE: A Client Credentials token is only detected if the `gty` attribute is set to `client-credentials`, which is a non-standardized attribute provided by Auth0. PRs are welcome for other identity providers)
- All other clients authenticating - i.e. OAuth2 that is not a Client Credentials token will only have the permissions specified in the `permissions` attribute.


## Installation

```bash
pip install fastapi-security
```

## Usage examples

Examples on how to use [can be found here](/examples).
