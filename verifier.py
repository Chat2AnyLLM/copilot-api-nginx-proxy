import os
import json
import time
import bcrypt
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

# JWT/JWKS libs
from jose import jwt, JWTError
from jwcrypto import jwk as jwcrypto_jwk

import logging

logging.basicConfig(level=os.getenv("VERIFIER_LOG_LEVEL", "INFO"))
logger = logging.getLogger("verifier")

app = FastAPI()

# Load API key configuration
# Support:
# - plain API_KEY (single legacy var)
# - API_KEYS (comma-separated plaintext keys)
# - API_KEYS_FILE_CONTAINER (path inside container mounted by docker-compose) or API_KEYS_FILE (legacy)
API_KEY = os.getenv("API_KEY", "")
API_KEYS_CSV = os.getenv("API_KEYS", "")
# Prefer API_KEYS_FILE_CONTAINER when running in docker; fall back to API_KEYS_FILE for legacy envs
API_KEYS_FILE = os.getenv("API_KEYS_FILE_CONTAINER", os.getenv("API_KEYS_FILE", ""))

# Collections to hold plaintext keys and bcrypt-hashed entries
PLAINTEXT_KEYS = {k for k in [API_KEY] if k}
BCRYPT_HASHED = []  # list of (user, hashed_bytes)

if API_KEYS_CSV:
    for k in (x.strip() for x in API_KEYS_CSV.split(",")):
        if k:
            PLAINTEXT_KEYS.add(k)

if API_KEYS_FILE and os.path.exists(API_KEYS_FILE):
    logger.info("Loading API keys from %s", API_KEYS_FILE)
    with open(API_KEYS_FILE, "r") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # support either "key" or "user:hashed_key"
            if ":" in line:
                user, hashed = line.split(":", 1)
                BCRYPT_HASHED.append((user.strip(), hashed.strip().encode()))
                logger.debug("Loaded bcrypt hash for user '%s' from line %d", user.strip(), lineno)
            else:
                # treat as bcrypt hash if it looks like one (starts with $2b$/$2a$), else plaintext
                if line.startswith("$2"):
                    BCRYPT_HASHED.append((None, line.strip().encode()))
                    logger.debug("Loaded bcrypt hash (no user) from line %d", lineno)
                else:
                    PLAINTEXT_KEYS.add(line)
                    logger.debug("Loaded plaintext key from line %d", lineno)


# JWKS / JWT helpers
JWKS_PATH = os.getenv("JWKS_PATH", "jwks.json")
# allow a common mounted certs path fallback
if not JWKS_PATH:
    JWKS_PATH = "jwks.json"
JWKS_FALLBACK_PATHS = [JWKS_PATH, "/certs/jwks.json", "./jwks.json"]

JWKS = None
_JWKS_MTIME = None


def _find_existing_jwks_path():
    for p in JWKS_FALLBACK_PATHS:
        try:
            if p and os.path.exists(p):
                logger.info("Found jwks.json at %s", p)
                return p
        except Exception:
            logger.exception("Error while checking jwks path %s", p)
            continue
    logger.info("No jwks.json found in fallback paths: %s", JWKS_FALLBACK_PATHS)
    return None


def load_local_jwks(path=None):
    """Load JWKS from a local file. Reloads when file mtime changes."""
    global JWKS, _JWKS_MTIME
    if path is None:
        path = _find_existing_jwks_path()
    if not path:
        JWKS = None
        _JWKS_MTIME = None
        return
    try:
        mtime = os.path.getmtime(path)
        if JWKS is not None and _JWKS_MTIME == mtime:
            logger.debug("JWKS file unchanged (mtime=%s), skipping reload", mtime)
            return
        with open(path, "r") as fh:
            JWKS = json.load(fh)
        _JWKS_MTIME = mtime
        logger.info("Loaded JWKS from %s (keys=%d)", path, len(JWKS.get('keys', [])))
    except Exception:
        JWKS = None
        _JWKS_MTIME = None
        logger.exception("Failed to load JWKS from %s", path)


def _get_jwk_for_kid(kid):
    if not JWKS:
        logger.debug("No JWKS loaded when looking for kid %s", kid)
        return None
    for k in JWKS.get("keys", []):
        if k.get("kid") == kid:
            logger.debug("Found JWK for kid %s", kid)
            return k
    logger.info("kid %s not found in loaded JWKS", kid)
    return None


def jwk_to_pem(jwk_dict):
    # jwcrypto expects a JSON string
    try:
        jw = jwcrypto_jwk.JWK.from_json(json.dumps(jwk_dict))
        pem = jw.export_to_pem(private_key=False, password=None)
        logger.debug("Converted JWK (kid=%s) to PEM, len=%d", jwk_dict.get('kid'), len(pem))
        return pem
    except Exception:
        logger.exception("Failed to convert JWK to PEM for kid %s", jwk_dict.get('kid'))
        raise


def verify_jwt_token(token: str):
    """Verify JWT using the local JWKS. Returns payload on success or raises JWTError."""
    # Load / refresh JWKS
    load_local_jwks()
    if not JWKS:
        logger.warning("Attempt to verify JWT but no JWKS available")
        raise JWTError("No JWKS available")

    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        logger.exception("Failed to parse JWT header")
        raise JWTError("Malformed JWT header")

    kid = header.get("kid")
    alg = header.get("alg", "RS256")
    logger.debug("Verifying JWT with kid=%s alg=%s", kid, alg)

    jwk_entry = _get_jwk_for_kid(kid)
    if not jwk_entry:
        logger.warning("No JWK found for kid %s", kid)
        raise JWTError(f"kid {kid} not found in JWKS")

    public_pem = jwk_to_pem(jwk_entry)

    # strict claim checks
    audience = os.getenv("JWT_AUDIENCE")
    issuer = os.getenv("JWT_ISSUER")

    # jose.jwt.decode will raise on invalid signature/claims
    try:
        payload = jwt.decode(
            token,
            public_pem,
            algorithms=[alg],
            audience=audience if audience else None,
            issuer=issuer if issuer else None,
        )
        logger.info("JWT verified successfully for kid %s subject %s", kid, payload.get("sub"))
        return payload
    except Exception:
        logger.exception("JWT verification failed for kid %s", kid)
        raise



@app.get("/healthz")
async def healthz():
    methods = ["plaintext"]
    if BCRYPT_HASHED:
        methods.append("bcrypt")
    # JWT support is active if a JWKS file exists
    load_local_jwks()
    if JWKS:
        methods.append("jwt/jwks")
    return {"status": "ok", "auth_methods": methods}


def check_token(token: str):
    # exact match plaintext
    if token in PLAINTEXT_KEYS:
        logger.debug("Plaintext key matched")
        return True, None

    # check bcrypt hashes
    for user, hashed in BCRYPT_HASHED:
        try:
            if bcrypt.checkpw(token.encode(), hashed):
                logger.info("Bcrypt key matched for user %s", user)
                return True, user
        except Exception:
            # ignore malformed hash entries
            logger.exception("Malformed bcrypt hash for user %s", user)
            continue
    logger.debug("No API key match found")
    return False, None


@app.get("/verify")
async def verify(request: Request):
    auth_header = request.headers.get("authorization")
    if not auth_header:
        logger.warning("Missing Authorization header in request")
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    # Support both "Bearer <key>" and "Authorization: <key>" formats
    token = auth_header
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
        logger.debug("Extracted Bearer token from Authorization header")
    else:
        logger.debug("Using raw Authorization header as token")

    # If the token looks like a JWT (has two dots), try JWT verification first
    if token.count('.') == 2:
        logger.debug("Token appears to be a JWT, attempting JWT verification")
        try:
            payload = verify_jwt_token(token)
            content = {"status": "ok"}
            # prefer sub claim for user identification
            if isinstance(payload, dict) and payload.get("sub"):
                content["user"] = payload.get("sub")
            logger.info("JWT verification succeeded, returning 200")
            return JSONResponse(status_code=200, content=content)
        except JWTError:
            logger.warning("JWT verification failed for token")
            # fall through to API key checks or fail explicitly
            raise HTTPException(status_code=401, detail="Invalid JWT")

    logger.debug("Token does not look like a JWT; attempting API key checks")
    ok, user = check_token(token)
    if ok:
        content = {"status": "ok"}
        if user:
            content["user"] = user
        logger.info("API key verification succeeded")
        return JSONResponse(status_code=200, content=content)

    logger.warning("API key verification failed")
    raise HTTPException(status_code=401, detail="Invalid API key")
