.PHONY: build run start-services stop-services clean test lint lint-fix help

# Default target
help:
	@echo "Available targets:"
	@echo "  build          - Build the bifrost binary"
	@echo "  run            - Start PostgreSQL/Dex in Docker and run bifrost locally"
	@echo "  start-services - Start PostgreSQL and Dex services only"
	@echo "  stop-services  - Stop PostgreSQL and Dex services"
	@echo "  clean          - Stop services and clean up"
	@echo "  test           - Run tests"
	@echo "  lint           - Run golangci-lint"
	@echo "  lint-fix       - Run golangci-lint with auto-fix"
	@echo "  help           - Show this help message"

# Build the bifrost binary
build:
	@echo "Building bifrost..."
	go mod tidy
	go build -o bifrost main.go
	@echo "Build complete: ./bifrost"

# Start PostgreSQL and Dex services
start-services:
	@echo "Starting PostgreSQL and Dex services..."
	docker-compose up -d
	@echo "Waiting for services to be ready..."
	@sleep 5
	@echo "Services started. PostgreSQL on :5432, Dex on :5556"

# Stop services
stop-services:
	@echo "Stopping services..."
	docker-compose down

# Run: start services and run bifrost locally
run: start-services build
	@echo "Starting bifrost locally..."
	@echo "Environment: DATABASE_URL=postgres://bifrost:bifrost123@localhost:5432/bifrost?sslmode=disable"
	DATABASE_URL=postgres://bifrost:bifrost123@localhost:5432/bifrost?sslmode=disable \
	OIDC_ISSUER_URL=http://localhost:5556 \
	OIDC_CLIENT_ID=bifrost-client \
	OIDC_CLIENT_SECRET=bifrost-secret \
	./bifrost -port 8080

# Clean up everything
clean: stop-services
	@echo "Cleaning up..."
	docker-compose down -v
	rm -f bifrost
	@echo "Cleanup complete"

# Run tests
test:
	@echo "Running tests..."
	go test ./...

# Run linter
lint:
	@echo "Running golangci-lint..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest" && exit 1)
	golangci-lint run --timeout=5m

# Run linter with auto-fix
lint-fix:
	@echo "Running golangci-lint with auto-fix..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest" && exit 1)
	golangci-lint run --fix --timeout=5m