# Bifrost Gov

A Bifrost HTTP service with OIDC authentication and PostgreSQL user storage.

## Features

- OIDC authentication using Dex
- PostgreSQL database for user storage
- GORM for database operations
- Plugin-based architecture

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

## Plugins

The application includes two built-in plugins:

1. **AuthPlugin (OIDC Authentication)**:
   - Validates OIDC ID tokens from Dex
   - Automatically stores/updates users in PostgreSQL
   - Links authenticated users to request context
   - Security-focused token validation

2. **SecureLoggingPlugin (Request Logging)**:
   - PostgreSQL-based request logging with user context
   - Tracks model usage, response times, token consumption
   - Links logs to authenticated users via foreign key
   - Security-conscious (no raw queries or sensitive data stored)
   - Automatically enabled when `EnableLogging=true` and `DATABASE_URL` is set

Both plugins are automatically loaded when the application starts.

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