import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI()

# Simple API key authentication
API_KEY = os.getenv("API_KEY", "")
SECRET_KEY = os.getenv("SECRET_KEY", "")

# Use either API_KEY or SECRET_KEY for validation
VALID_KEYS = {key for key in [API_KEY, SECRET_KEY] if key}


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "auth_method": "api_key"}


@app.get("/verify")
async def verify(request: Request):
    auth_header = request.headers.get("authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    # Support both "Bearer <key>" and "Authorization: <key>" formats
    token = auth_header
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
    
    if not VALID_KEYS:
        raise HTTPException(status_code=500, detail="No API keys configured")
    
    if token in VALID_KEYS:
        return JSONResponse(status_code=200, content={"status": "ok"})
    
    raise HTTPException(status_code=401, detail="Invalid API key")
