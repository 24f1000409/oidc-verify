from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import jwt
from jwt import InvalidTokenError

app = FastAPI()

# ---------------------------------------------------------------------------
# YOUR ASSIGNED VALUES — already filled in from your screenshot
# ---------------------------------------------------------------------------
ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-1vnkm5oh.apps.exam.local"

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""
# ---------------------------------------------------------------------------


class TokenRequest(BaseModel):
    token: str


@app.post("/verify")
async def verify(request: TokenRequest):
    try:
        # jwt.decode automatically checks: signature, exp (expiry), aud, iss
        # when we pass audience= and issuer=. If any fail, it raises.
        payload = jwt.decode(
            request.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
        )
        return {
            "valid": True,
            "email": payload.get("email"),
            "sub": payload.get("sub"),
            "aud": payload.get("aud"),
        }
    except InvalidTokenError:
        # Covers: bad signature, expired, wrong audience, wrong issuer,
        # tampered payload, malformed token — anything invalid.
        return JSONResponse(status_code=401, content={"valid": False})


@app.get("/")
async def root():
    return {"status": "ok", "service": "oidc-token-verification"}
