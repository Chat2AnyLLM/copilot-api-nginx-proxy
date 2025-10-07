import os
import bcrypt
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

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
    with open(API_KEYS_FILE, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # support either "key" or "user:hashed_key"
            if ":" in line:
                user, hashed = line.split(":", 1)
                BCRYPT_HASHED.append((user.strip(), hashed.strip().encode()))
            else:
                # treat as bcrypt hash if it looks like one (starts with $2b$/$2a$), else plaintext
                if line.startswith("$2"):
                    BCRYPT_HASHED.append((None, line.strip().encode()))
                else:
                    PLAINTEXT_KEYS.add(line)


@app.get("/healthz")
async def healthz():
    methods = ["plaintext"]
    if BCRYPT_HASHED:
        methods.append("bcrypt")
    return {"status": "ok", "auth_methods": methods}


def check_token(token: str):
    # exact match plaintext
    if token in PLAINTEXT_KEYS:
        return True, None

    # check bcrypt hashes
    for user, hashed in BCRYPT_HASHED:
        try:
            if bcrypt.checkpw(token.encode(), hashed):
                return True, user
        except Exception:
            # ignore malformed hash entries
            continue
    return False, None


@app.get("/verify")
async def verify(request: Request):
    auth_header = request.headers.get("authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    # Support both "Bearer <key>" and "Authorization: <key>" formats
    token = auth_header
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]

    if not (PLAINTEXT_KEYS or BCRYPT_HASHED):
        raise HTTPException(status_code=500, detail="No API keys configured")

    ok, user = check_token(token)
    if ok:
        content = {"status": "ok"}
        if user:
            content["user"] = user
        return JSONResponse(status_code=200, content=content)

    raise HTTPException(status_code=401, detail="Invalid API key")
