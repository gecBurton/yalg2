# Bifrost Gov

A government-focused AI proxy built on [Bifrost](https://github.com/maximhq/bifrost) with OIDC authentication and PostgreSQL logging.

## Architecture

- **Authentication**: OIDC-based with JWT tokens and web sessions
- **Authorization**: Middleware protects `/v1/*`, `/api/*`, `/metrics` routes
- **Logging**: PostgreSQL with metadata only (no request/response bodies)
- **Database**: PostgreSQL with GORM for users, sessions, and logs

## Quick Start

```bash
# Start services
docker compose up -d

# Build and run
go build -o bifrost main.go
./bifrost -app-dir ./data -port 8080
```

## Services

- **Application**: http://localhost:8080
- **PostgreSQL**: localhost:5432 (bifrost/bifrost123)
- **Dex OIDC**: http://localhost:5556

## Test Users

- **admin@example.com** / password
- **test@example.com** / password

## API Usage

```bash
# Get auth token via web login at http://localhost:8080/auth/login
# Or use direct OIDC flow

# Use token for API calls
curl -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}' \
     http://localhost:8080/v1/chat/completions
```

## Development

```bash
# Run tests
go test ./...

# Run with coverage
go test -cover ./internal/...
```

## Configuration

Required environment variables:
- `DATABASE_URL`: PostgreSQL connection string
- `PORT`: Server port (default: 8080)

See `.env.example` for full configuration options.