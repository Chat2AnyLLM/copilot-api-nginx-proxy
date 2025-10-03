# copilot-api-nginx-proxy

A small nginx reverse-proxy configuration and Docker Compose setup for running a secure proxy in front of the Copilot API backend.

Features
- TLS-terminating nginx proxy
- Secure upstream TLS to the copilot-api service
- Docker Compose for local development and deployment

Requirements
- Docker and Docker Compose

Quickstart
1. Copy the example environment file if present and adjust values:
   cp .env.example .env
2. Start the services:
   docker compose up -d
3. Verify the proxy is serving HTTPS (adjust host/port as configured):
   curl -vk https://localhost/

Configuration
Set the following environment variables or mount equivalent files into the nginx container:
- COPILOT_API_HOST: upstream host (default: copilot_api:4111)
- PROXY_PORT: port nginx listens on (default: 443)
- TLS_CERT_PATH, TLS_KEY_PATH: filesystem paths to TLS certificate and key inside the container

Self-signed certificates
- If the upstream or proxy uses a self-signed certificate during development, Node.js clients may reject TLS connections. For local testing you can temporarily disable Node.js TLS verification by exporting:

  export NODE_TLS_REJECT_UNAUTHORIZED='0'

  Use this only for local development and never in production.

Development
- Tail logs during development:
  docker compose logs -f nginx
- Make configuration changes in nginx.conf and restart the nginx service.

Contributing
Contributions welcome. Open an issue or submit a pull request.

License
MIT
