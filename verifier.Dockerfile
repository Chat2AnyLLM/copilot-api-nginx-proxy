FROM python:3.11-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    JWKS_URL= \
    JWKS_REFRESH_SECONDS=3600 \
    JWT_AUDIENCE=your_audience_here

RUN pip install --no-cache-dir fastapi uvicorn[standard] python-jose httpx bcrypt

COPY verifier.py .
COPY jwks.json .

CMD ["uvicorn", "verifier:app", "--host", "0.0.0.0", "--port", "5002"]
