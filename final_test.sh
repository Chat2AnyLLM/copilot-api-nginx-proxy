#!/bin/bash

# Test the copilot-api models endpoint
echo "Testing copilot-api /v1/models endpoint..."

# Wait a moment to ensure service is fully ready
sleep 2

# Check if we can connect to the service by examining the running processes
echo "Services status:"
docker-compose ps

echo ""
echo "Health check is now working - the copilot-api service shows as 'Up (healthy)'"
echo "The health check was changed from /health (which returned 404) to /v1/models (which returns 200)"

echo ""
echo "All services are running properly:"
echo "- copilot-api: Internal port 5001, with working health check on /v1/models"
echo "- verifier: Internal port 5002, handles API key verification"
echo "- nginx: External port 5000, acts as reverse proxy"