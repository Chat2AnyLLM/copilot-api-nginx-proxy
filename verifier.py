import json
import time
import threading
from typing import Dict, Optional
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError
import os

app = FastAPI()

JWKS_LOCK = threading.Lock()
JWKS: Dict = {"keys": []}
LAST_REFRESH = 0.0

JWKS_URL = os.getenv("JWKS_URL")  # Optional remote JWKS endpoint
JWKS_REFRESH_SECONDS = int(os.getenv("JWKS_REFRESH_SECONDS", "3600"))
LOCAL_JWKS_PATH = os.getenv("LOCAL_JWKS_PATH", "/app/jwks.json")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "your_audience_here")
ALLOWED_ALGS = os.getenv("JWT_ALLOWED_ALGS", "RS256,RS384,RS512").split(",")


def _load_local_jwks() -> None:
    global JWKS
    try:
        with open(LOCAL_JWKS_PATH, "r") as f:
            data = json.load(f)
            if "keys" in data:
                JWKS = data
    except FileNotFoundError:
        pass


def _refresh_remote_jwks() -> None:
    global JWKS, LAST_REFRESH
    if not JWKS_URL:
        return
    try:
        resp = httpx.get(JWKS_URL, timeout=5.0)
        resp.raise_for_status()
        data = resp.json()
        if "keys" in data:
            with JWKS_LOCK:
                JWKS = data
                LAST_REFRESH = time.time()
    except Exception:
        # Silent failure; keep last good keys
        pass


def ensure_jwks_fresh() -> None:
    global LAST_REFRESH
    now = time.time()
    if (now - LAST_REFRESH) > JWKS_REFRESH_SECONDS:
        _refresh_remote_jwks()


@app.on_event("startup")
def startup_event():
    _load_local_jwks()
    _refresh_remote_jwks()


def get_key_for_kid(kid: str) -> Dict:
    with JWKS_LOCK:
        for key in JWKS.get("keys", []):
            if key.get("kid") == kid:
                return key
    raise HTTPException(status_code=401, detail="Unknown key ID")


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "keys": len(JWKS.get('keys', []))}


@app.get("/verify")
async def verify(request: Request):
    ensure_jwks_fresh()
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    token = auth_header.split(" ", 1)[1]
    try:
        header = jwt.get_unverified_header(token)
        alg = header.get("alg")
        if alg not in ALLOWED_ALGS:
            raise HTTPException(status_code=401, detail="Disallowed alg")
        jwk = get_key_for_kid(header["kid"])
        if jwk.get("alg") and jwk["alg"] != alg:
            raise HTTPException(status_code=401, detail="alg mismatch")

        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[alg],
            audience=JWT_AUDIENCE,
            options={
                "verify_aud": bool(JWT_AUDIENCE),
            },
        )
        return JSONResponse(status_code=200, content={"status": "ok", "sub": payload.get("sub")})
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
