# copilot-api-nginx-proxy

A small nginx reverse-proxy configuration and Docker Compose setup for running a secure proxy in front of the Copilot API backend.

Features
- TLS-terminating nginx proxy
- Authentication gateway (auth_request) that delegates API key / JWT validation to a lightweight Python verifier service
- Secure upstream TLS to the copilot-api service
- Docker Compose for local development and deployment

Requirements
- Docker and Docker Compose
- A GitHub token if you run the embedded `copilot-api` builder (set `GITHUB_TOKEN`)

Quickstart
1. Copy the example environment file and set values:
   cp .env.example .env
   Edit `.env` and populate the required variables described below.
2. Start the services:
   docker compose up -d --build
3. Verify the proxy is serving HTTPS (adjust host/port as configured):
   curl -vk https://localhost:5000/

Configuration
This repository composes three main services:
- `copilot-api` — the upstream Copilot API service (built from `Dockerfile.copilot`).
- `verifier` — small FastAPI app that validates incoming requests using either API keys or JWT/JWKS.
- `nginx` — TLS-terminating reverse proxy that uses `auth_request` to call the `verifier` service.

Environment variables are documented in `.env.example`. Important variables include:
- `GITHUB_TOKEN` — required by the `copilot-api` builder if you run that service (set to a GitHub PAT with appropriate scopes).
- `HOST_CERTS_DIR` — host directory mounted into Nginx at `/etc/nginx/certs` containing `copilot.crt` and `copilot.key`.
- `API_KEY` — API key accepted by the `verifier` service. Provide at least one.

TLS / Certificates
- Provide TLS cert and key files in the host path referenced by `HOST_CERTS_DIR`. They should be named `copilot.crt` and `copilot.key`.
- For development you may use self-signed certs, but do not disable TLS verification in production. If testing with Node.js clients only, you can temporarily set `NODE_TLS_REJECT_UNAUTHORIZED=0` locally (not recommended for general use).

Development
- Tail logs during development:
  docker compose logs -f nginx verifier copilot-api
- The `verifier` service is implemented in `verifier.py`. It supports multiple verification modes:
  - Plaintext API keys via `API_KEY` or `API_KEYS` (comma-separated).
  - Bcrypt-hashed keys loaded from `API_KEYS_FILE`. Lines may be `user:$2b$...` or a plaintext key.
  - JWT validation via `JWKS_URL`, `JWKS_REFRESH_SECONDS`, and `JWT_AUDIENCE`.

Example `API_KEYS_FILE` entries (one per line):

```
alice:$2b$12$wV... (bcrypt hash of alice's key)
bob:$2b$12$7Q...   (bcrypt hash of bob's key)
# a plaintext key (not recommended in production)
plainkey123
```

To generate a bcrypt hash locally (Python):

```
import bcrypt
pw = b"my-secret-key"
print(bcrypt.hashpw(pw, bcrypt.gensalt()).decode())
```

Make configuration changes in `nginx.conf` and restart the nginx service.

Contributing
Contributions welcome. Open an issue or submit a pull request.

License
MIT
