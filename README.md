# copilot-api-nginx-proxy

A small nginx reverse-proxy configuration and Docker Compose setup for running a secure proxy in front of the Copilot API backend.

Features
- TLS-terminating nginx proxy with enhanced security headers
- Authentication gateway (auth_request) that delegates API key / JWT validation to a lightweight Python verifier service
- Secure upstream TLS to the copilot-api service
- Docker Compose for local development and deployment
- JWT token minting endpoint (/token) for exchanging API keys for short-lived JWT tokens
- Remote JWKS support with automatic fetching and caching
- Enhanced rate limiting at the nginx level
- Improved security with constant-time comparisons and algorithm whitelisting
- **NEW**: Flexible image building from copilot-api source repository (instead of using npx)

## Building from Source

This repository now supports building the `copilot-api` service directly from the source code instead of using npx. The Dockerfile (`Dockerfile.copilot.fromrepo`) implements a multi-stage build that:

- Clones the copilot-api repository from https://github.com/ericc-ch/copilot-api
- Builds the project using bun
- Creates a production image with a non-root user
- Includes health checks

This approach provides greater flexibility to customize the copilot-api behavior and allows you to use your own modifications to the source code.

## Quickstart

1. Copy the example environment file and set values:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and populate the required variables described below.

2. Start the services:
   ```bash
   docker compose up -d --build
   ```

3. Verify the proxy is serving HTTPS (adjust host/port as configured):
   ```bash
   curl -vk https://localhost:5000/
   ```

## Configuration

This repository composes three main services:
- `copilot-api` — the upstream Copilot API service (now built from `Dockerfile.copilot.fromrepo`).
- `verifier` — small FastAPI app that validates incoming requests using either API keys or JWT/JWKS.
- `nginx` — TLS-terminating reverse proxy that uses `auth_request` to call the `verifier` service.

Environment variables are documented in `.env.example`. Important variables include:
- `GITHUB_TOKEN` — required by the `copilot-api` builder if you run that service (set to a GitHub PAT with appropriate scopes).
- `HOST_CERTS_DIR` — host directory mounted into Nginx at `/etc/nginx/certs` containing `copilot.crt` and `copilot.key`.
- `API_KEY` — API key accepted by the `verifier` service. Provide at least one.
- `JWKS_URL` — (Optional) HTTPS URL to fetch JWKS from for remote JWKS support.
- `JWKS_TTL` — (Optional) Time-to-live for cached remote JWKS in seconds (default: 300).
- `JWT_TTL` — (Optional) Token time-to-live in seconds for JWT tokens minted by the /token endpoint (default: 3600).
- `JWT_AUDIENCE` — (Optional) Audience claim for JWT tokens.
- `JWT_ISSUER` — (Optional) Issuer claim for JWT tokens.

TLS / Certificates
- Provide TLS cert and key files in the host path referenced by `HOST_CERTS_DIR`. They should be named `copilot.crt` and `copilot.key`.
- For development you may use self-signed certs, but do not disable TLS verification in production. If testing with Node.js clients only, you can temporarily set `NODE_TLS_REJECT_UNAUTHORIZED=0` locally (not recommended for general use).

Development
- Tail logs during development:
  docker compose logs -f nginx verifier copilot-api
- The `verifier` service is implemented in `verifier.py`. It supports multiple verification modes:
  - Plaintext API keys via `API_KEY` or `API_KEYS` (comma-separated).
  - Bcrypt-hashed keys loaded from `API_KEYS_FILE`. Lines may be `user:$2b$...` or a plaintext key.
  - JWT validation via local or remote JWKS (using `JWKS_URL` with automatic fetching and caching).
  - JWT token minting via the `/token` endpoint for exchanging valid API keys for short-lived JWT tokens.

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

Authentication flow (enhanced verifier implementation)

When a client sends an authenticated request the flow is:

1. Client -> Nginx
   - Client calls the proxied API and includes credentials in the Authorization header (either `Bearer <token>` or raw `<token>`).
2. Nginx -> Verifier (auth_request)
   - Nginx calls the verifier's `/verify` endpoint and forwards the Authorization header.
3. Verifier extracts token
   - If header starts with `Bearer `, the token portion is extracted.
4. Verifier decides path
   - If token looks like a JWT (contains two dots):
     a. Load JWKS (from remote URL if `JWKS_URL` is configured, else local file).
     b. Parse JWT header, find `kid` in JWKS, convert JWK -> PEM, verify signature and claims (`exp`, `aud`, `iss`).
     c. On success return 200 with optional `user` set from `sub` claim.
     d. On failure return 401.
   - Else (not a JWT):
     a. Check plaintext API keys (from `API_KEY`, `API_KEYS`, or plaintext lines in `API_KEYS_FILE`) using constant-time comparison.
     b. If not found, iterate bcrypt hashes from `API_KEYS_FILE` and run `bcrypt.checkpw`. If matched, return 200 and include associated user if present.
     c. If no match, return 401.
5. Nginx enforces result
   - Nginx allows the proxied request to proceed to upstream on 200. On 401/500 it denies the request.

Additionally, clients can exchange valid API keys for JWT tokens using the `/token` endpoint:
1. Client -> Verifier
   - Client makes a POST request to `/token` with a valid API key in the Authorization header.
2. Verifier validates API key
   - Checks plaintext or bcrypt hashed keys as in the verification flow.
3. Verifier mints JWT
   - Finds a private JWK in the loaded JWKS.
   - Signs a new JWT with configurable claims (`sub`, `aud`, `iss`, `exp`).
   - Returns the signed JWT with metadata.
4. Client receives JWT
   - Can use the JWT for subsequent requests until expiration.

Mermaid flowchart (added to README):

```mermaid
flowchart TD
  A["Client request\n(Authorization header)"] --> B["Nginx auth_request -> /verify"]
  B --> C{Token has two dots?}
  C -- Yes --> D["Verifier: load local JWKS\nfind JWK by kid"]
  D --> E{Signature valid?}
  E -- Yes --> F{Claims OK?}
  F -- Yes --> G["200 OK\n(user = sub)"]
  F -- No --> H["401 Invalid JWT claims"]
  E -- No --> H
  C -- No --> I["Verifier: check PLAINTEXT_KEYS"]
  I -- Match --> G
  I -- No --> J["Check BCRYPT_HASHED\nwith bcrypt.checkpw"]
  J -- Match --> G
  J -- No --> K["401 Invalid API key"]

  G --> L["Nginx allows request to upstream"]
  H --> M["Nginx denies request"]
  K --> M
```

```mermaid
sequenceDiagram
  participant Client
  participant Nginx
  participant Verifier
  participant Upstream

  Client->>Nginx: HTTPS request (Authorization header)
  Nginx->>Verifier: auth_request /verify (forwards headers)
  Verifier->>Verifier: Extract token from header
  alt Token is JWT
    Verifier->>Verifier: Load local JWKS and find key by kid
    Verifier->>Verifier: Verify signature and claims (exp/aud/iss)
    Verifier-->>Nginx: 200 OK (user=sub)
  else Token is API key
    Verifier->>Verifier: Check PLAINTEXT_KEYS
    alt Plaintext match
      Verifier-->>Nginx: 200 OK
    else
      Verifier->>Verifier: Check BCRYPT_HASHED via bcrypt.checkpw
      alt Bcrypt match
        Verifier-->>Nginx: 200 OK (user)
      else
        Verifier-->>Nginx: 401 Invalid API key
      end
    end
  end

  alt Verifier returned 200
    Nginx->>Upstream: Proxy request to upstream
    Upstream-->>Nginx: Response
    Nginx-->>Client: Response
  else Verifier returned 401/500
    Nginx-->>Client: 401/500 error
  end
```

Notes:
- JWKS must contain only public key material. For local-only setups place `jwks.json` in the repo root or mount it at `/certs/jwks.json`.
- Configure `JWT_AUDIENCE` and `JWT_ISSUER` for claim checks when issuing tokens.
- The verifier will auto-reload `jwks.json` when the file mtime changes.

## Security Enhancements

Several security improvements have been implemented in the latest version:

### Constant-time API Key Comparison
API key verification now uses constant-time comparison (`hmac.compare_digest`) to prevent timing attacks that could potentially leak information about valid keys.

### JWT Algorithm Whitelisting
The JWT verification process now implements algorithm whitelisting to prevent algorithm confusion attacks. Only secure algorithms are allowed:
- RS256, RS384, RS512 (RSA PKCS#1 v1.5)
- ES256, ES384, ES512 (ECDSA)
- PS256, PS384, PS512 (RSA PSS)

### Enhanced Nginx Security Headers
Nginx configuration now includes additional security headers:
- Strict-Transport-Security (HSTS) for enforced HTTPS
- X-XSS-Protection to prevent cross-site scripting attacks
- Referrer-Policy to control referrer information
- Content-Security-Policy to prevent unauthorized resource loading

### Rate Limiting
Enhanced rate limiting has been implemented at the nginx level:
- API requests: 10 requests per second per IP
- Authentication requests: 5 requests per minute per IP
- Configurable burst limits to handle traffic spikes

## JWT Token Minting (/token endpoint)

The verifier service now includes a `/token` endpoint that allows clients with valid API keys to exchange them for short-lived JWT tokens. This provides a more secure authentication mechanism by using temporary tokens instead of long-lived API keys.

### How it works:
1. Client makes a POST request to `/token` with a valid API key in the Authorization header
2. The verifier validates the API key (plaintext or bcrypt)
3. If valid, the verifier signs a new JWT using a private JWK from the loaded JWKS
4. The signed JWT is returned to the client with an expiration time (default 1 hour)

### Configuration:
- `JWT_TTL` - Token time-to-live in seconds (default: 3600)
- `JWT_AUDIENCE` - Audience claim for the JWT
- `JWT_ISSUER` - Issuer claim for the JWT

### Usage example:
```bash
# Exchange API key for JWT token
curl -X POST https://localhost:5000/token \
  -H "Authorization: Bearer YOUR_API_KEY"

# Response:
# {
#   "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Imt...",
#   "expires_in": 3600,
#   "kid": "key1",
#   "alg": "RS256"
# }

# Use the JWT token for subsequent requests
curl https://localhost:5000/v1/completions \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6Imt..."
```

### JWKS Requirements:
To use the `/token` endpoint, your JWKS file must contain at least one private key (with private parameters like `d` for RSA keys or `k` for symmetric keys). Public-only JWKS files can be used for JWT verification but not for token minting.

## Remote JWKS Support

The verifier can now fetch JWKS from remote URLs in addition to local files:

- `JWKS_URL` - HTTPS URL to fetch JWKS from (optional)
- `JWKS_TTL` - Time-to-live for cached remote JWKS in seconds (default: 300)

When `JWKS_URL` is configured, the verifier will:
1. Attempt to fetch JWKS from the remote URL
2. Cache the result with automatic refresh based on `JWKS_TTL`
3. Fall back to local JWKS file if remote fetching fails

Security features:
- Only HTTPS URLs are allowed for remote JWKS fetching
- JWKS structure is validated before use
- Algorithm whitelisting prevents algorithm confusion attacks



Contributing
Contributions welcome. Open an issue or submit a pull request.

License
MIT
