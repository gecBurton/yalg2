# Bifrost Gov

A government-focused AI proxy built on [Bifrost](https://github.com/maximhq/bifrost) with OIDC authentication and comprehensive logging.

## Architecture

### Authentication Architecture

This application implements a unified authentication system using systematic middleware to protect all API routes:

#### 1. Authentication Middleware (`internal/middleware/auth.go`)
- **Purpose**: Centralized JWT authentication for all protected routes
- **Implementation**: FastHTTP middleware that validates Bearer tokens before requests reach handlers
- **Protected Routes**: All `/v1/*` and `/api/*` endpoints, plus `/metrics`
- **Public Routes**: Authentication flows (`/auth/*`), UI assets (`/`, `/ui/*`, `/static/*`)
- **Flow**: Validates JWT tokens, injects user context, passes through to handlers

#### 2. Web Authentication (`plugins/auth/`)
- **Purpose**: Browser-based OIDC login flows for the web interface  
- **Routes**: `/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/status`
- **Flow**: Redirects users to Dex OIDC provider, handles callbacks, manages sessions
- **Storage**: Uses cookies and database sessions for web users
- **Implementation**: `plugins/auth/handler.go`

#### 3. Standard Bifrost Handlers
- **Purpose**: Use official Bifrost completion handlers without custom auth wrapping
- **Routes**: `/v1/chat/completions`, `/v1/text/completions` (protected by middleware)
- **Flow**: Standard Bifrost request handling with authentication handled upstream
- **Implementation**: Uses `handlers.NewCompletionHandler()` from Bifrost HTTP transport

#### 4. Shared OIDC Services (`plugins/auth/plugin.go`)
- **Purpose**: Common OIDC token verification and user management
- **Provides**: JWT verifier, database operations, user storage
- **Shared by**: Both web handlers and authentication middleware

#### Why This Architecture?

**Systematic Protection**: Authentication middleware automatically protects all API routes without requiring individual handler modifications.

**Header Access Solution**: Since Bifrost plugins cannot access HTTP headers (like `Authorization: Bearer <token>`), authentication happens at the web server level before requests reach Bifrost handlers.

**Cleaner Implementation**: Eliminates the need for custom authentication wrappers around each endpoint - standard Bifrost handlers work with systematic authentication.

## Features

- **Systematic Authentication**: Middleware-based JWT validation protecting all API routes
- **OIDC Integration**: Browser-based authentication flows using Dex OIDC provider
- **PostgreSQL Storage**: User and session data with GORM for database operations
- **Comprehensive Logging**: Request logging with authenticated user context
- **Standard Bifrost Handlers**: Uses official completion handlers with upstream authentication
- **Fail-fast Database**: Requires DATABASE_URL environment variable for startup

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

### Environment Variables

- `PORT`: Server port (default: 8080)
- `APP_DIR`: Application data directory
- `OIDC_ISSUER_URL`: OIDC provider issuer URL
- `OIDC_CLIENT_ID`: OIDC client identifier
- `OIDC_CLIENT_SECRET`: OIDC client secret
- `DATABASE_URL`: PostgreSQL connection string


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

### Authentication (`plugins/auth/` + `internal/middleware/`)

- **`plugins/auth/plugin.go`** - OIDC services and shared user management
- **`plugins/auth/handler.go`** - Web authentication routes (login/logout/callback/status)
- **`plugins/auth/models.go`** - User and Session data models
- **`internal/middleware/auth.go`** - Systematic JWT authentication middleware for all API routes

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