# FastAPI Security Example App

To try out:

```bash
pip install fastapi-security uvicorn
export BASIC_AUTH_CREDENTIALS='[{"username": "user1", "password": "test"}]'
export AUTH_JWKS_URL='https://my-auth0-tenant.eu.auth0.com/.well-known/jwks.json'
export AUTH_AUDIENCES='["my-audience"]'
export PERMISSION_OVERRIDES='{"user1": ["products:create"]}'
uvicorn app1:app
```
