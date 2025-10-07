FROM python:3.11-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir fastapi uvicorn[standard] python-jose httpx bcrypt jwcrypto requests

COPY verifier.py .
COPY jwks.json .

CMD ["uvicorn", "verifier:app", "--host", "0.0.0.0", "--port", "5002"]
