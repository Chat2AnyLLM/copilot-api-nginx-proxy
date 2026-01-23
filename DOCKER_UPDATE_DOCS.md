# Updated Docker Setup Documentation

## Changes Made

This repository has been updated to build the `copilot-api` service from the source repository instead of using npx.

### Old Approach
- Used `npx copilot-api@latest` directly in the Dockerfile
- Dockerfile.copilot contained a simple Alpine setup with npx execution

### New Approach
- Created Dockerfile.copilot.fromrepo that clones the copilot-api repository from https://github.com/ericc-ch/copilot-api
- Builds the project from source using bun
- Implements a multi-stage Docker build for better security and smaller final image
- Uses a non-root user for improved security
- Includes health checks

### Files Changed

1. **Dockerfile.copilot.fromrepo**: New Dockerfile that builds copilot-api from source repository
2. **docker-compose.yml**: Updated to use Dockerfile.copilot.fromrepo instead of Dockerfile.copilot

### Benefits

- **Flexibility**: Can now customize the copilot-api source code as needed
- **Control**: Full control over the build process and dependencies
- **Security**: Non-root user execution and multi-stage build
- **Reproducibility**: Exact source code version is controlled by the build

### Building and Running

To build and run the updated setup:

```bash
# Build the services
docker compose build

# Start the services
docker compose up -d

# Or build and start in one command
docker compose up -d --build
```

### Environment Variables

The same environment variables are supported as before:
- `GITHUB_TOKEN`: Your GitHub token for authentication
- `ACCOUNT_TYPE`: Account type (enterprise or personal)
- All other existing variables for the verifier and nginx services