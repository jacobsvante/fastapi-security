# FastAPI-Security Example App

To try out:

```bash
pip install fastapi-security uvicorn
export OIDC_DISCOVERY_URL='https://my-auth0-tenant.eu.auth0.com/.well-known/openid-configuration'
export OAUTH2_AUDIENCES='["my-audience"]'
export BASIC_AUTH_CREDENTIALS='[{"username": "user1", "password": "test"}]'
export PERMISSION_OVERRIDES='{"user1": ["products:create"]}'
uvicorn app1:app
```

You would need to replace the `my-auth0-tenant.eu.auth0.com` part to make it work.
