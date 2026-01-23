import os
import json
import time
import bcrypt
import hmac
from collections import defaultdict
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

# JWT/JWKS libs
from jose import jwt, JWTError
from jwcrypto import jwk as jwcrypto_jwk

import logging

logging.basicConfig(level=os.getenv("VERIFIER_LOG_LEVEL", "INFO"))
logger = logging.getLogger("verifier")

app = FastAPI()

# Allowed JWT algorithms to prevent algorithm confusion attacks
ALLOWED_JWT_ALGORITHMS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}

# Rate limiting has been disabled
# rate_limits = defaultdict(list)
#
# def check_rate_limit(client_ip: str, endpoint: str, max_requests: int = 10, window: int = 60):
#     """Simple in-memory rate limiting. Replace with Redis for production."""
#     now = time.time()
#     key = f"{client_ip}:{endpoint}"
#
#     # Clean old requests
#     rate_limits[key] = [req_time for req_time in rate_limits[key] if now - req_time < window]
#
#     if len(rate_limits[key]) >= max_requests:
#         return False
#
#     rate_limits[key].append(now)
#     return True
#
# @app.middleware("http")
# async def rate_limit_middleware(request: Request, call_next):
#     client_ip = request.client.host if request.client else "unknown"
#
#     if request.url.path in ["/verify", "/token"]:
#         if not check_rate_limit(client_ip, request.url.path, max_requests=5, window=60):
#             return JSONResponse(status_code=429, content={"error": "Too many requests"})
#
#     response = await call_next(request)
#     return response

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


def _find_existing_jwks_path():
    # The original _find_existing_jwks_path implementation remains above; this placeholder
    # ensures our helper functions are located after jwk_to_pem in the file.
    pass


def _find_private_jwk():
    """Return the first JWK in the loaded JWKS that contains private key material (e.g. 'd' for RSA/EC or 'k' for oct).
    Returns None if no private JWK is available.
    """
    ensure_jwks_loaded()
    if not JWKS:
        logger.debug("No JWKS loaded when searching for a private JWK")
        return None
    for k in JWKS.get("keys", []):
        # RFC7517 private parameters: RSA has 'd', EC has 'd', symmetric keys ('oct') have 'k'
        if isinstance(k, dict) and ("d" in k or (k.get("kty") == "oct" and "k" in k)):
            logger.info("Found private JWK for kid=%s", k.get("kid"))
            return k
    logger.info("No private JWK found in JWKS")
    return None


def jwk_to_private_pem(jwk_dict):
    """Convert a private JWK dict to a PEM-encoded private key (bytes).
    Uses jwcrypto to perform the conversion. Raises on failure.
    """
    try:
        jw = jwcrypto_jwk.JWK.from_json(json.dumps(jwk_dict))
        pem = jw.export_to_pem(private_key=True, password=None)
        logger.debug("Converted private JWK (kid=%s) to PEM, len=%d", jwk_dict.get('kid'), len(pem))
        return pem
    except Exception:
        logger.exception("Failed to convert private JWK to PEM for kid %s", jwk_dict.get('kid'))
        raise


@app.post("/token")
async def mint_token(request: Request):
    """Mint a short-lived JWT for a validated API key.

    Clients present an API key in the Authorization header (Bearer <api_key> or raw <api_key>).
    If the key validates (plaintext or bcrypt), the server will sign a JWT using a private
    JWK from the loaded jwks.json. The endpoint prefers an existing private JWK; if none
    is available it returns a 500 error.
    """
    auth_header = request.headers.get("authorization")
    if not auth_header:
        logger.warning("Missing Authorization header in /token request")
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    token = auth_header
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]

    ok, user = check_token(token)
    if not ok:
        logger.info("Unauthorized attempt to mint token")
        raise HTTPException(status_code=401, detail="Invalid API key")

    # subject: prefer user from bcrypt file, else mark as api_key
    subject = user if user else "api_key"

    # Build claims
    now = int(time.time())
    ttl = int(os.getenv("JWT_TTL", "3600"))  # seconds
    payload = {"sub": subject, "iat": now, "exp": now + ttl}
    audience = os.getenv("JWT_AUDIENCE")
    issuer = os.getenv("JWT_ISSUER")
    if audience:
        payload["aud"] = audience
    if issuer:
        payload["iss"] = issuer

    # Find a private key to sign with
    private_jwk = _find_private_jwk()
    if not private_jwk:
        logger.warning("No private JWK available to sign token; deny /token request")
        raise HTTPException(status_code=500, detail="No signing key available")

    alg = private_jwk.get("alg", "RS256")
    kid = private_jwk.get("kid")
    try:
        private_pem = jwk_to_private_pem(private_jwk)
    except Exception:
        logger.exception("Failed to obtain PEM for private JWK kid=%s", kid)
        raise HTTPException(status_code=500, detail="Failed to prepare signing key")

    # Encode JWT with kid header
    headers = {"kid": kid} if kid else None
    try:
        signed = jwt.encode(payload, private_pem, algorithm=alg, headers=headers)
        logger.info("Minted JWT for subject=%s kid=%s exp=%s", subject, kid, payload.get("exp"))
        return JSONResponse(status_code=200, content={"token": signed, "expires_in": ttl, "kid": kid, "alg": alg})
    except Exception:
        logger.exception("Failed to sign JWT for subject=%s", subject)
        raise HTTPException(status_code=500, detail="Failed to sign token")


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

    # Validate algorithm against whitelist to prevent algorithm confusion attacks
    if alg not in ALLOWED_JWT_ALGORITHMS:
        logger.warning("Unsupported or dangerous JWT algorithm: %s", alg)
        raise JWTError(f"Unsupported algorithm: {alg}")

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
            algorithms=list(ALLOWED_JWT_ALGORITHMS),  # Use full whitelist instead of single algorithm
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
    # exact match plaintext with constant-time comparison
    token_bytes = token.encode('utf-8')
    for key in PLAINTEXT_KEYS:
        key_bytes = key.encode('utf-8')
        if hmac.compare_digest(token_bytes, key_bytes):
            logger.debug("Plaintext key matched")
            return True, None

    # check bcrypt hashes (already constant-time)
    for user, hashed in BCRYPT_HASHED:
        try:
            if bcrypt.checkpw(token_bytes, hashed):
                logger.info("Bcrypt key matched for user %s", user)
                return True, user
        except Exception:
            logger.exception("Malformed bcrypt hash for user %s", user)
            continue
    logger.debug("No API key match found")
    return False, None


@app.get("/verify")
async def verify(request: Request):
    # First check for x-api-key header (treat as API key only)
    api_key_header = request.headers.get("x-api-key")
    if api_key_header:
        logger.debug("Found x-api-key header, treating as API key")
        ok, user = check_token(api_key_header)
        if ok:
            content = {"status": "ok"}
            if user:
                content["user"] = user
            logger.info("x-api-key verification succeeded for user=%s, returning 200", user)
            return JSONResponse(status_code=200, content=content)
        else:
            logger.warning("x-api-key verification failed, returning 401 to caller")
            raise HTTPException(status_code=401, detail="Invalid API key")

    # Fall back to Authorization header (existing logic)
    auth_header = request.headers.get("authorization")
    if not auth_header:
        logger.warning("Missing Authorization header in request (and no x-api-key header)")
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
