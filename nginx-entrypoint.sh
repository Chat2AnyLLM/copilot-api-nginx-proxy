#!/bin/bash
set -e

# Build rate limiting zones
RATE_LIMIT_ZONES=""
if [ -n "$RATE_LIMIT_API" ] || [ -n "$RATE_LIMIT_AUTH" ]; then
    if [ -n "$RATE_LIMIT_API" ]; then
        RATE_LIMIT_ZONES="${RATE_LIMIT_ZONES}limit_req_zone \$binary_remote_addr zone=api:10m rate=${RATE_LIMIT_API};"
        RATE_LIMIT_ZONES="${RATE_LIMIT_ZONES}\n    "
    fi
    if [ -n "$RATE_LIMIT_AUTH" ]; then
        RATE_LIMIT_ZONES="${RATE_LIMIT_ZONES}limit_req_zone \$binary_remote_addr zone=auth:10m rate=${RATE_LIMIT_AUTH};"
    fi
fi

# Build API rate limiting directives
API_RATE_LIMIT=""
if [ -n "$RATE_LIMIT_API" ]; then
    API_RATE_LIMIT="limit_req zone=api burst=${RATE_LIMIT_API_BURST:-20} nodelay;
            limit_req_status 429;"
fi

# Build auth rate limiting directives
AUTH_RATE_LIMIT=""
if [ -n "$RATE_LIMIT_AUTH" ]; then
    AUTH_RATE_LIMIT="limit_req zone=auth burst=${RATE_LIMIT_AUTH_BURST:-10} nodelay;
            limit_req_status 429;"
fi

# Replace placeholders in template
sed -e "s|\${RATE_LIMIT_ZONES}|${RATE_LIMIT_ZONES}|g" \
    -e "s|\${API_RATE_LIMIT}|${API_RATE_LIMIT}|g" \
    -e "s|\${AUTH_RATE_LIMIT}|${AUTH_RATE_LIMIT}|g" \
    /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

# Start nginx
exec nginx -g "daemon off;"
