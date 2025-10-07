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

# Remote JWKS support (optional)
import requests as _requests

JWKS_URL = os.getenv("JWKS_URL", "").strip() or None
JWKS_TTL = int(os.getenv("JWKS_TTL", "300"))  # seconds

# Cached remote JWKS state
_REMOTE_JWKS = None
_REMOTE_JWKS_FETCHED_AT = None


def _validate_jwks_structure(jwks_obj):
    if not isinstance(jwks_obj, dict):
        raise ValueError("JWKS not a JSON object")
    keys = jwks_obj.get("keys")
    if not isinstance(keys, list):
        raise ValueError("JWKS missing 'keys' array")
    for k in keys:
        if not isinstance(k, dict) or "kid" not in k or "kty" not in k:
            raise ValueError("Each JWK must be an object containing at least 'kid' and 'kty'")


def _fetch_remote_jwks():
    global _REMOTE_JWKS, _REMOTE_JWKS_FETCHED_AT
    if not JWKS_URL:
        return None
    # Use cached until TTL expires
    now = time.time()
    if _REMOTE_JWKS and _REMOTE_JWKS_FETCHED_AT and (now - _REMOTE_JWKS_FETCHED_AT) < JWKS_TTL:
        return _REMOTE_JWKS
    # Only allow HTTPS URLs
    if not JWKS_URL.lower().startswith("https://"):
        logger.warning("JWKS_URL must use https://; ignoring %s", JWKS_URL)
        return None
    try:
        resp = _requests.get(JWKS_URL, timeout=5)
        resp.raise_for_status()
        jwks_obj = resp.json()
        _validate_jwks_structure(jwks_obj)
        _REMOTE_JWKS = jwks_obj
        _REMOTE_JWKS_FETCHED_AT = now
        logger.info("Fetched JWKS from %s (keys=%d)", JWKS_URL, len(jwks_obj.get("keys", [])))
        return _REMOTE_JWKS
    except Exception:
        logger.exception("Failed to fetch/validate JWKS from %s; using cached or local JWKS if available", JWKS_URL)
        return _REMOTE_JWKS  # may be None or last-successful


def ensure_jwks_loaded():
    """Load JWKS from remote URL (cached) if configured, else local file(s)."""
    global JWKS
    # Prefer remote JWKS if configured
    if JWKS_URL:
        remote = _fetch_remote_jwks()
        if remote:
            JWKS = remote
            return
        # otherwise fall through to local file (cached or new load)
    # local fallback (existing behavior)
    load_local_jwks()



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
    """Verify JWT using the local JWKS. Returns payload on success or raises JWTError.

    Logging expanded to provide visibility into header parsing, selected JWK, and a
    safe subset of claims (sub/aud/iss/exp/iat) on success. The raw JWT and any
    sensitive claim values are intentionally not logged.
    """
    # Load / refresh JWKS
    ensure_jwks_loaded()
    if not JWKS:
        logger.warning("Attempt to verify JWT but no JWKS available")
        raise JWTError("No JWKS available")

    try:
        header = jwt.get_unverified_header(token)
        logger.debug("Parsed JWT header keys: %s", list(header.keys()))
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
        # Log a safe, small set of claims for observability without exposing full token
        safe_claims = {k: payload.get(k) for k in ("sub", "aud", "iss", "exp", "iat") if k in payload}
        logger.info("JWT verified successfully for kid=%s subject=%s safe_claims=%s", kid, payload.get("sub"), safe_claims)
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
    ensure_jwks_loaded()
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

    # Record that the verifier received a request and the approximate token type
    token_type = "jwt" if token.count('.') == 2 else "api_key"
    logger.info("Received /verify request from %s with token_type=%s", request.client.host if request.client else "unknown", token_type)

    # If the token looks like a JWT (has two dots), try JWT verification first
    if token_type == "jwt":
        logger.debug("Token appears to be a JWT, attempting JWT verification")
        try:
            payload = verify_jwt_token(token)
            content = {"status": "ok"}
            # prefer sub claim for user identification
            if isinstance(payload, dict) and payload.get("sub"):
                content["user"] = payload.get("sub")
            logger.info("JWT verification succeeded, returning 200 for user=%s", content.get("user"))
            return JSONResponse(status_code=200, content=content)
        except JWTError:
            logger.warning("JWT verification failed for token; returning 401 to caller")
            # fall through to API key checks or fail explicitly
            raise HTTPException(status_code=401, detail="Invalid JWT")

    logger.debug("Token does not look like a JWT; attempting API key checks")
    ok, user = check_token(token)
    if ok:
        content = {"status": "ok"}
        if user:
            content["user"] = user
        logger.info("API key verification succeeded for user=%s, returning 200", user)
        return JSONResponse(status_code=200, content=content)

    logger.warning("API key verification failed, returning 401 to caller")
    raise HTTPException(status_code=401, detail="Invalid API key")
