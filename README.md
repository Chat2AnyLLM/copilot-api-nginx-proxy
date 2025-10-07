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

Authentication flow (new verifier implementation)

When a client sends an authenticated request the flow is:

1. Client -> Nginx
   - Client calls the proxied API and includes credentials in the Authorization header (either `Bearer <token>` or raw `<token>`).
2. Nginx -> Verifier (auth_request)
   - Nginx calls the verifier's `/verify` endpoint and forwards the Authorization header.
3. Verifier extracts token
   - If header starts with `Bearer `, the token portion is extracted.
4. Verifier decides path
   - If token looks like a JWT (contains two dots):
     a. Load local JWKS (prefers `JWKS_PATH` or `/certs/jwks.json`).
     b. Parse JWT header, find `kid` in JWKS, convert JWK -> PEM, verify signature and claims (`exp`, `aud`, `iss`).
     c. On success return 200 with optional `user` set from `sub` claim.
     d. On failure return 401.
   - Else (not a JWT):
     a. Check plaintext API keys (from `API_KEY`, `API_KEYS`, or plaintext lines in `API_KEYS_FILE`).
     b. If not found, iterate bcrypt hashes from `API_KEYS_FILE` and run `bcrypt.checkpw`. If matched, return 200 and include associated user if present.
     c. If no match, return 401.
5. Nginx enforces result
   - Nginx allows the proxied request to proceed to upstream on 200. On 401/500 it denies the request.

Mermaid flowchart (added to README):

```mermaid
flowchart TD
  A[Client request\n(Authorization header)] --> B[Nginx auth_request -> /verify]
  B --> C{Token contains '.' '.'?}
  C -- Yes --> D[Verifier: load local JWKS\nfind JWK by kid]
  D --> E{Signature valid?}
  E -- Yes --> F{Claims OK (aud/iss/exp)?}
  F -- Yes --> G[200 OK\n(user = sub)]
  F -- No --> H[401 Invalid JWT claims]
  E -- No --> H
  C -- No --> I[Verifier: check PLAINTEXT_KEYS]
  I -- Match --> G
  I -- No --> J[Check BCRYPT_HASHED with bcrypt.checkpw]
  J -- Match --> G
  J -- No --> K[401 Invalid API key]

  G --> L[Nginx allows request to upstream]
  H --> M[Nginx denies request]
  K --> M
```

Notes:
- JWKS must contain only public key material. For local-only setups place `jwks.json` in the repo root or mount it at `/certs/jwks.json`.
- Configure `JWT_AUDIENCE` and `JWT_ISSUER` for claim checks when issuing tokens.
- The verifier will auto-reload `jwks.json` when the file mtime changes.



Contributing
Contributions welcome. Open an issue or submit a pull request.

License
MIT
