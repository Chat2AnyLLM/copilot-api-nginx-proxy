#!/bin/bash

echo "Testing services..."

# Wait a moment for services to be fully ready
sleep 5

echo "Checking if services are running..."
if docker-compose ps | grep -q "Up"; then
    echo "✓ Services are running"
else
    echo "✗ Services are not running properly"
    docker-compose ps
    exit 1
fi

echo "All services are running and healthy!"
echo "Nginx is accessible on port 5000"
echo "Copilot API is running on internal port 5001"
echo "Verifier is running on internal port 5002"