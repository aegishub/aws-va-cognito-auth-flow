# main.py
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from jose import jwt, JWTError
from pydantic import BaseModel
from typing import Optional
import httpx
import logging
import os
import hashlib
import base64
from urllib.parse import urlencode

app = FastAPI()

# === CONFIG ===
REGION = os.getenv("REGION")  # e.g. 'eu-central-1'
USER_POOL_ID = os.getenv("USER_POOL_ID")  # e.g. 'eu-central-1_examplepoolid'
COGNITO_DOMAIN = os.getenv("COGNITO_DOMAIN")  # Hosted UI domain
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
BASE_URL = os.getenv("BASE_URL")  # e.g. 'https://test.my-site.com'
REDIRECT_URI = f"{BASE_URL}/callback"
ACCOUNT_ID = os.getenv("ACCOUNT_ID")  # e.g., '458672271618'
VA_SIGNER = f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:verified-access-instance/{{vai_id}}"
VA_JWKS_URL = f"https://public-keys.prod.verified-access.{REGION}.amazonaws.com/{{key_id}}"
COGNITO_JWKS_URL = f"https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}/.well-known/jwks.json"
TOKEN_URL = f"https://{COGNITO_DOMAIN}/oauth2/token"
LOGOUT_URL = f"https://{COGNITO_DOMAIN}/logout"
LOGIN_URL = f"https://{COGNITO_DOMAIN}/login"
ISSUER = f"https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}"

#print("DEBUG COGNITO_JWKS_URL:", COGNITO_JWKS_URL)
#print("DEBUG TOKEN_URL:", TOKEN_URL)


# Налаштування логування
logger = logging.getLogger("uvicorn.error")

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Логування лише статусу та тексту помилки
    logger.error(f"HTTPException: {exc.status_code} - {exc.detail}")
    # Повертаємо стандартну JSON-відповідь
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled Exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"},
    )

# === MODELS ===
class TokenResponse(BaseModel):
    id_token: str
    access_token: str
    refresh_token: Optional[str]
    token_type: str
    expires_in: int

# === HELPERS ===
async def exchange_code_for_token(code: str) -> TokenResponse:
    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    print("DEBUG exchange token:", data)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    async with httpx.AsyncClient() as client:
        r = await client.post(TOKEN_URL, data=data, headers=headers)
        if r.status_code != 200:
            print("Cognito token exchange error:", r.status_code, r.text)
        r.raise_for_status()
        return TokenResponse(**r.json())

async def get_public_keys():
    async with httpx.AsyncClient() as client:
        r = await client.get(COGNITO_JWKS_URL)
        r.raise_for_status()
        return r.json()["keys"]

async def get_verified_access_keys(region: str, key_id: str) -> str:
    # Формуємо URL для отримання публічного ключа
    va_jwks_url = VA_JWKS_URL.format(key_id=key_id)
    # print("DEBUG VA_JWKS_URL:", va_jwks_url)

    # Виконуємо запит до Verified Access JWKS URL
    async with httpx.AsyncClient() as client:
        response = await client.get(va_jwks_url)
        # print("DEBUG VA_JWKS_URL response status:", response.status_code)
        if response.status_code != 200:
            print("DEBUG VA_JWKS_URL response error:", response.text)
        response.raise_for_status()

        return response.text  # Повертаємо публічний ключ


def verify_at_hash(access_token: str, at_hash: str):
    # Розрахунок хешу access_token
    print(f"DEBUG: Starting at_hash verification")
    #print(f"DEBUG: Access token: {access_token}")
    #print(f"DEBUG: Expected at_hash: {at_hash}")
    hash_digest = hashlib.sha256(access_token.encode()).digest()
    calculated_at_hash = base64.urlsafe_b64encode(hash_digest[:16]).decode().rstrip("=")
    #print(f"DEBUG: Calculated at_hash: {calculated_at_hash}")

    # Порівняння з at_hash
    if calculated_at_hash != at_hash:
        print("DEBUG: at_hash verification failed")
        raise HTTPException(status_code=401, detail="Invalid access token hash")
    print("DEBUG: at_hash verification successful")


async def decode_jwt(token: str, access_token: Optional[str] = None, token_type: Optional[str] = None):
    # Визначаємо тип токена
    if not token_type:
        token_type = "access_token" if access_token else "id_token"

    #print(f"DEBUG: Decoding token type {token_type}")
    #print(f"DEBUG: Received access_token: {access_token}")
    headers = jwt.get_unverified_header(token)
    kid = headers.get("kid")
    if not kid:
        print("DEBUG: Missing 'kid' in token headers")
        raise HTTPException(status_code=401, detail="Missing 'kid' in token headers")
    #print(f"DEBUG: JWT headers: {headers}")

    keys = await get_public_keys()
    key = next((k for k in keys if k.get("kid") == kid), None)
    if not key:
        print(f"DEBUG: Public key not found for kid: {kid}")
        raise HTTPException(status_code=401, detail=f"Public key not found for kid: {kid}")

    try:
        decoded_token = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=ISSUER,
            options={"verify_at_hash": False}
        )
        # print(f"DEBUG: Decoded token claims: {decoded_token}")

        # Перевірка at_hash, якщо передано access_token
        if access_token:
            if "at_hash" in decoded_token:
                print(f"DEBUG: Verifying at_hash: {decoded_token['at_hash']}")
                verify_at_hash(access_token, decoded_token["at_hash"])
            else:
                print("DEBUG: at_hash not found in id_token")
                raise HTTPException(status_code=401, detail="at_hash not found in id_token")

        # Перевірка строку дії токена
        import time
        current_time = int(time.time())
        if "exp" not in decoded_token:
            print("DEBUG: Missing 'exp' in token claims")
            raise HTTPException(status_code=401, detail="Token does not contain expiration time")
        if decoded_token.get("exp") < current_time:
            print("DEBUG: Token has expired")
            raise HTTPException(status_code=401, detail="Token has expired")

        print("DEBUG: Token verification successful")
        return decoded_token

    except JWTError as e:
        print(f"DEBUG: JWT decode error: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

async def validate_verified_access_token(token: str):
    # Розшифрування заголовка JWT
    headers = jwt.get_unverified_header(token)
    key_id = headers.get("kid")
    signer = headers.get("signer")

    # Діагностика заголовків JWT
    #print("DEBUG VA_JWT HEADERS:", headers)
    #print("DEBUG VA_key_id:", key_id)
    #print("DEBUG VA_signer:", signer)

    if not key_id or not signer:
        raise HTTPException(status_code=401, detail="Invalid Verified Access token header")

    # Отримання vai_id із `signer`
    vai_id = signer.split("/")[-1]  # Витягуємо `vai-09fb539346b9bcc06`

    # Формування очікуваного `signer`
    expected_signer = VA_SIGNER.format(vai_id=vai_id)
    # print("DEBUG expected_signer:", expected_signer)

    if signer != expected_signer:
        raise HTTPException(status_code=401, detail="Invalid Verified Access signer")

    # Отримання публічного ключа через get_verified_access_keys
    public_key = await get_verified_access_keys(REGION, key_id)

    try:
        # Перевірка підпису та декодування токена
        decoded_token = jwt.decode(
            token,
            public_key,
            algorithms=["ES384"],  # Алгоритм підпису
            options={"verify_aud": False},  # Вимкнути перевірку аудиторії, якщо не потрібна
        )

        # Діагностика claims токена
        # print("DEBUG VA_JWT_CLAIMS:", decoded_token)

        # Перевірка наявності поля additional_user_context
        additional_user_context = decoded_token.get("additional_user_context")
        if not additional_user_context:
            raise HTTPException(status_code=401, detail="Token does not contain additional_user_context")

        # Перевірка наявності поля exp у additional_user_context
        if "exp" not in additional_user_context:
            raise HTTPException(status_code=401, detail="Token does not contain expiration time (exp) in additional_user_context")

        # Перевірка строку дії токена
        import time
        current_time = int(time.time())
        if additional_user_context["exp"] < current_time:
            raise HTTPException(status_code=401, detail="Verified Access token has expired")

        return decoded_token

    except JWTError as e:
        print("DEBUG VA_JWT decode error:", str(e))
        raise HTTPException(status_code=401, detail=f"Invalid Verified Access token: {str(e)}")

# === ROUTES ===

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.middleware("http")
async def verify_amzn_context(request: Request, call_next):
    if request.url.path == "/health":
        return await call_next(request)

    # print("DEBUG Verified Access Headers:", request.headers)

    va_context = request.headers.get("x-amzn-ava-user-context")

    if not va_context:
        logger.error("Missing Verified Access context")
        raise HTTPException(status_code=403, detail="Missing Verified Access context")

    try:
        # Валідація Verified Access токена
        decoded_va_token = await validate_verified_access_token(va_context)
        print("DEBUG Verified Access token claims:", decoded_va_token)
    except HTTPException as e:
        logger.error(f"Verified Access validation failed: {e.detail}")
        raise e

    # Продовжуємо обробку запиту
    response = await call_next(request)
    return response

@app.get("/callback")
async def callback(code: Optional[str] = None):
    if not code:
        raise HTTPException(status_code=400, detail="Missing code")

    # Обмін коду на токени
    tokens = await exchange_code_for_token(code)
    #print("DEBUG Tokens:", tokens)

    # Перевірка id_token
    id_token_claims = await decode_jwt(tokens.id_token, access_token=tokens.access_token, token_type="id_token")

    # Перевірка access_token
    access_token_claims = await decode_jwt(tokens.access_token, token_type="access_token")

    response = RedirectResponse(url="/")
    response.set_cookie(key="id_token", value=tokens.id_token, httponly=True, secure=True, samesite="None")
    response.set_cookie(key="access_token", value=tokens.access_token, httponly=True, secure=True, samesite="None")
    return response

@app.get("/signout")
async def signout():
    cognito_logout_url = (
        f"{LOGOUT_URL}?client_id={CLIENT_ID}&logout_uri={BASE_URL}/logout"
    )
    response = RedirectResponse(url=cognito_logout_url)
    response.delete_cookie("id_token")
    response.delete_cookie("access_token")
    #response.delete_cookie("AWSVAAuthSessionCookie-00")
    #response.delete_cookie("AWSVAAuthSessionCookie-01")

    return response


@app.get("/auth/verify")
async def verify(request: Request):
    print("DEBUG: Starting /auth/verify")
    id_token = request.cookies.get("id_token")
    access_token = request.cookies.get("access_token")
    #print(f"DEBUG: id_token from cookies: {id_token}")
    #print(f"DEBUG: access_token from cookies: {access_token}")

    if not id_token or not access_token:
        print("DEBUG: Missing tokens in cookies")
        raise HTTPException(status_code=401, detail="Missing tokens in cookies")

    try:
        print("DEBUG: Verifying id_token")
        id_token_claims = await decode_jwt(id_token, access_token=access_token, token_type="id_token")

        print("DEBUG: Verifying access_token")
        access_token_claims = await decode_jwt(access_token, token_type="access_token")
    except HTTPException as e:
        print(f"DEBUG: Token verification failed: {str(e)}")
        raise e

    # Перевірка строку дії id_token
    import time
    current_time = int(time.time())
    # print(f"DEBUG: Current time: {current_time}, id_token exp: {id_token_claims.get('exp')}")
    if id_token_claims.get("exp") < current_time:
        print("DEBUG: id_token has expired")
        raise HTTPException(status_code=401, detail="id_token has expired")

    # Перевірка строку дії access_token
    # print(f"DEBUG: Current time: {current_time}, access_token exp: {access_token_claims.get('exp')}")
    if access_token_claims.get("exp") < current_time:
        print("DEBUG: access_token has expired")
        raise HTTPException(status_code=401, detail="access_token has expired")

    user = id_token_claims.get("username") or id_token_claims.get("sub") or id_token_claims.get("cognito:username")
    print(f"DEBUG: Verified user: {user}")
    return {"status": "ok", "user": user}

@app.get("/login")
async def start_login():
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "scope": "openid email",
        "redirect_uri": REDIRECT_URI,
    }
    url = f"{LOGIN_URL}?{urlencode(params)}"
    print("DEBUG login redirect URL:", url)
    return RedirectResponse(url=url)

@app.get("/")
async def home():
    return {"message": "Welcome to the FastAPI auth backend!"}
