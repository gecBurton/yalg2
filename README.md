# Bifrost Gov

A government-focused AI proxy built on [Bifrost](https://github.com/maximhq/bifrost) with OIDC authentication and comprehensive logging.

## Architecture

### Authentication Architecture

This application implements a dual authentication system to handle both web-based and API-based access:

#### 1. Web Authentication (`plugins/auth/`)
- **Purpose**: Browser-based OIDC login flows for the web interface
- **Routes**: `/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/status`
- **Flow**: Redirects users to Dex OIDC provider, handles callbacks, manages sessions
- **Storage**: Uses cookies and database sessions for web users
- **Implementation**: `plugins/auth/handler.go`

#### 2. API Authentication (`pkg/handlers/auth_completion.go`)
- **Purpose**: JWT token validation for programmatic API access
- **Routes**: `/v1/chat/completions`, `/v1/text/completions` (with auth wrapper)
- **Flow**: Validates Bearer tokens in Authorization headers, injects user context
- **Storage**: Stateless JWT validation, user context passed to logging
- **Implementation**: `pkg/handlers/auth_completion.go`

#### 3. Shared OIDC Services (`plugins/auth/plugin.go`)
- **Purpose**: Common OIDC token verification and user management
- **Provides**: JWT verifier, database operations, user storage
- **Shared by**: Both web handlers and API handlers use these services

#### Why This Architecture?

**Different Access Patterns**: Web browsers need redirect-based OIDC flows with cookies, while API clients need stateless JWT token validation.

**Header Access Limitation**: Bifrost plugins cannot access HTTP headers (like `Authorization: Bearer <token>`), so API authentication must happen at the HTTP handler level before requests reach Bifrost.

**Clean Separation**: Web auth handles human users, API auth handles programmatic access, shared services provide common functionality.

## Features

- Dual authentication: OIDC web flows + JWT API validation
- PostgreSQL database for user and session storage
- GORM for database operations
- Comprehensive request logging with user context
- Fail-fast database requirement

## Quick Start

### 1. Start the Development Environment

```bash
# Start PostgreSQL and Dex
docker-compose up -d

# Wait for services to be ready
docker-compose logs -f
```

### 2. Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env with your configuration (defaults should work for development)
```

### 3. Build and Run Bifrost

```bash
# Build the application
go build -o bifrost main.go

# Run with development configuration
./bifrost -app-dir ./data -port 8080
```

## Services

### PostgreSQL
- **Host**: localhost:5432
- **Database**: bifrost
- **Username**: bifrost
- **Password**: bifrost123

### Dex (OIDC Provider)
- **Issuer URL**: http://localhost:5556
- **Auth UI**: http://localhost:5556/auth
- **Client ID**: bifrost-client
- **Client Secret**: bifrost-secret

### Test Users

The Dex configuration includes test users:

- **Email**: admin@example.com
- **Password**: password
- **User ID**: 08a8684b-db88-4b73-90a9-3cd1661f5466

- **Email**: test@example.com  
- **Password**: password
- **User ID**: 41331323-6f44-45e6-b3b9-0c8b77e6c062

## Testing OIDC Authentication

1. Start the services: `docker-compose up -d`
2. Start Bifrost: `./bifrost`
3. Navigate to Dex auth URL: http://localhost:5556/auth
4. Use test credentials to authenticate
5. Check that users are stored in PostgreSQL

## Configuration

### OIDC AuthPlugin Example

```go
config := &OIDCConfig{
    IssuerURL:   "http://localhost:5556",
    ClientID:    "bifrost-client",
    ClientSecret: "bifrost-secret",
    DatabaseURL: "postgres://bifrost:bifrost123@localhost:5432/bifrost?sslmode=disable",
}

authPlugin, err := NewAuthPlugin(config)
```

### Environment Variables

- `PORT`: Server port (default: 8080)
- `APP_DIR`: Application data directory
- `OIDC_ISSUER_URL`: OIDC provider issuer URL
- `OIDC_CLIENT_ID`: OIDC client identifier
- `OIDC_CLIENT_SECRET`: OIDC client secret
- `DATABASE_URL`: PostgreSQL connection string

## Database Schema

The application automatically creates a `users` table with the following schema:

```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    sub VARCHAR(255) UNIQUE NOT NULL,  -- OIDC subject identifier
    email VARCHAR(255),                -- User email
    name VARCHAR(255),                 -- User display name
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Development

### Prerequisites

- Go 1.24+
- Docker and Docker Compose

### Building

```bash
go mod tidy
go build -o bifrost main.go
```

### Running Tests

```bash
go test ./...
```

## Components

### Authentication (`plugins/auth/` + `pkg/handlers/`)

- **`plugins/auth/plugin.go`** - OIDC services and shared user management
- **`plugins/auth/handler.go`** - Web authentication routes (login/logout/callback/status)
- **`plugins/auth/models.go`** - User and Session data models
- **`pkg/handlers/auth_completion.go`** - API JWT authentication wrapper for completion endpoints

### Logging (`plugins/logging/`)

- **`plugins/logging/plugin.go`** - SecureLoggingPlugin for request/response logging with user context
- **`plugins/logging/models.go`** - LogEntry data model
- **`plugins/logging/handler.go`** - Metrics and logging web interface

### Infrastructure (`pkg/database/`)

- **`pkg/database/connection.go`** - PostgreSQL connection utilities

The application requires a PostgreSQL database connection and will fail to start without `DATABASE_URL`.

## Docker Compose Services

- **postgres**: PostgreSQL 15 database
- **dex**: Dex OIDC provider v2.37.0

Stop services:
```bash
docker-compose down
```

Remove data:
```bash
docker-compose down -v
```