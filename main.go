// Package http provides an HTTP service using FastHTTP that exposes endpoints
// for text and chat completions using various AI model providers (OpenAI, Anthropic, Bedrock, Mistral, Ollama, etc.).
//
// The HTTP service provides the following main endpoints:
//   - /v1/text/completions: For text completion requests
//   - /v1/chat/completions: For chat completion requests
//   - /v1/mcp/tool/execute: For MCP tool execution requests
//   - /providers/*: For provider configuration management
//
// Configuration is handled through a JSON config file, high-performance ConfigStore, and environment variables:
//   - Use -app-dir flag to specify the application data directory (contains config.json and logs)
//   - Use -port flag to specify the server port (default: 8080)
//   - When no config file exists, common environment variables are auto-detected (OPENAI_API_KEY, ANTHROPIC_API_KEY, MISTRAL_API_KEY)
//
// ConfigStore Features:
//   - Pure in-memory storage for ultra-fast config access
//   - Environment variable processing for secure configuration management
//   - Real-time configuration updates via HTTP API
//   - Explicit persistence control via POST /config/save endpoint
//   - Provider-specific meta config support (Azure, Bedrock, Vertex)
//   - Thread-safe operations with concurrent request handling
//   - Statistics and monitoring endpoints for operational insights
//
// Performance Optimizations:
//   - Configuration data is processed once during startup and stored in memory
//   - Ultra-fast memory access eliminates I/O overhead on every request
//   - All environment variable processing done upfront during configuration loading
//   - Thread-safe concurrent access with read-write mutex protection
//
// Example usage:
//
//	go run main.go -app-dir ./data -port 8080
//	after setting provider API keys like OPENAI_API_KEY in the environment.
//
// Integration Support:
// Bifrost supports multiple AI provider integrations through dedicated HTTP endpoints.
// Each integration exposes API-compatible endpoints that accept the provider's native request format,
// automatically convert it to Bifrost's unified format, process it, and return the expected response format.
//
// Integration endpoints follow the pattern: /{provider}/{provider_api_path}
// Examples:
//   - OpenAI: POST /openai/v1/chat/completions (accepts OpenAI ChatCompletion requests)
//   - GenAI:  POST /genai/v1beta/models/{model} (accepts Google GenAI requests)
//   - Anthropic: POST /anthropic/v1/messages (accepts Anthropic Messages requests)
//
// This allows clients to use their existing integration code without modification while benefiting
// from Bifrost's unified model routing, fallbacks, monitoring capabilities, and high-performance configuration management.
//
// NOTE: Streaming is supported for chat completions via Server-Sent Events (SSE)
package main

import (
	// "embed"
	"flag"
	"log"

	"mime"
	"os"
	"path"
	"path/filepath"
	"strings"

	"context"

	"bifrost-gov/pkg/database"
	"bifrost-gov/plugins/auth"
	"bifrost-gov/plugins/logging"

	"github.com/fasthttp/router"
	bifrost "github.com/maximhq/bifrost/core"
	schemas "github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/bifrost-http/handlers"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
	"gorm.io/gorm"
)

// Command line flags
var (
	port   string // Port to run the server on
	appDir string // Application data directory
)

// accountWrapper wraps lib.BaseAccount to implement the schemas.Account interface
// with the correct method signature
type accountWrapper struct {
	*lib.BaseAccount
}

// GetKeysForProvider implements schemas.Account interface with context parameter
func (a *accountWrapper) GetKeysForProvider(ctx *context.Context, providerKey schemas.ModelProvider) ([]schemas.Key, error) {
	// Call the underlying method without context since BaseAccount doesn't support it yet
	return a.BaseAccount.GetKeysForProvider(providerKey)
}

// init initializes command line flags and validates required configuration.
// It sets up the following flags:
//   - port: Server port (default: 8080)
//   - app-dir: Application data directory (default: current directory)
func init() {
	flag.StringVar(&port, "port", "8080", "Port to run the server on")
	flag.StringVar(&appDir, "app-dir", ".", "Application data directory (contains config.json and logs)")
	flag.Parse()
}

// corsMiddleware handles CORS headers for localhost requests
func corsMiddleware(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		origin := string(ctx.Request.Header.Peek("Origin"))

		// Allow requests from localhost on any port
		if strings.HasPrefix(origin, "http://localhost:") || strings.HasPrefix(origin, "https://localhost:") ||
			strings.HasPrefix(origin, "http://127.0.0.1:") || strings.HasPrefix(origin, "https://127.0.0.1:") {
			ctx.Response.Header.Set("Access-Control-Allow-Origin", origin)
		}

		ctx.Response.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		ctx.Response.Header.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		ctx.Response.Header.Set("Access-Control-Allow-Credentials", "true")
		ctx.Response.Header.Set("Access-Control-Max-Age", "86400")

		// Handle preflight OPTIONS requests
		if string(ctx.Method()) == "OPTIONS" {
			ctx.SetStatusCode(fasthttp.StatusOK)
			return
		}

		next(ctx)
	}
}

// uiHandler serves the local index.html file
func uiHandler(ctx *fasthttp.RequestCtx) {
	// Get the request path
	requestPath := string(ctx.Path())

	// Clean the path to prevent directory traversal
	cleanPath := path.Clean(requestPath)

	// For root path or any SPA route, serve index.html
	if cleanPath == "/" || !strings.Contains(filepath.Base(cleanPath), ".") {
		// Serve index.html for root and SPA routes
		data, err := os.ReadFile("index.html")
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.SetBodyString("404 - index.html not found")
			return
		}

		// Set content type for HTML
		ctx.SetContentType("text/html; charset=utf-8")

		// Set cache headers for HTML (no cache for SPA)
		ctx.Response.Header.Set("Cache-Control", "no-cache")

		// Send the file content
		ctx.SetBody(data)
		return
	}

	// For other files (CSS, JS, images, etc.), try to serve them from the current directory
	// Remove leading slash for file system access
	filePath := strings.TrimPrefix(cleanPath, "/")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// File not found, serve index.html as fallback for SPA routing
		data, err := os.ReadFile("index.html")
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.SetBodyString("404 - File not found")
			return
		}

		ctx.SetContentType("text/html; charset=utf-8")
		ctx.Response.Header.Set("Cache-Control", "no-cache")
		ctx.SetBody(data)
		return
	}

	// Read the file
	data, err := os.ReadFile(filePath)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString("500 - Internal server error")
		return
	}

	// Set content type based on file extension
	ext := filepath.Ext(filePath)
	contentType := mime.TypeByExtension(ext)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	ctx.SetContentType(contentType)

	// Set cache headers
	if ext == ".html" {
		ctx.Response.Header.Set("Cache-Control", "no-cache")
	} else {
		ctx.Response.Header.Set("Cache-Control", "public, max-age=3600")
	}

	// Send the file content
	ctx.SetBody(data)
}

// main is the entry point of the application.
// It:
// 1. Initializes Prometheus collectors for monitoring
// 2. Reads and parses configuration from the specified config file
// 3. Initializes the Bifrost client with the configuration
// 4. Sets up HTTP routes for text and chat completions
// 5. Starts the HTTP server on the specified port
//
// The server exposes the following endpoints:
//   - POST /v1/text/completions: For text completion requests
//   - POST /v1/chat/completions: For chat completion requests
//   - GET /metrics: For Prometheus metrics
func main() {
	// Ensure app directory exists
	if err := os.MkdirAll(appDir, 0755); err != nil {
		log.Fatalf("failed to create app directory %s: %v", appDir, err)
	}

	// Derive paths from app-dir
	configPath := filepath.Join(appDir, "config.json")

	logger := bifrost.NewDefaultLogger(schemas.LogLevelInfo)

	// Initialize high-performance configuration store with caching
	store, err := lib.NewConfigStore(logger)
	if err != nil {
		log.Fatalf("failed to initialize config store: %v", err)
	}

	// Load configuration from JSON file into the store with full preprocessing
	// This processes environment variables and stores all configurations in memory for ultra-fast access
	if err := store.LoadFromConfig(configPath); err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// Create account backed by the high-performance store (all processing is done in LoadFromConfig)
	// The account interface now benefits from ultra-fast config access times via in-memory storage
	baseAccount := lib.NewBaseAccount(store)
	account := &accountWrapper{BaseAccount: baseAccount}

	loadedPlugins := []schemas.Plugin{}

	// Initialize shared database connection if available
	databaseURL := os.Getenv("DATABASE_URL")
	var sharedDB *gorm.DB
	if databaseURL != "" {
		db, err := database.NewPostgresConnection(databaseURL)
		if err != nil {
			log.Fatalf("Failed to create database connection: %v", err)
		}
		sharedDB = db
		log.Println("Shared database connection established")

		// Initialize auth plugin for API request validation
		oidcConfig := &auth.OIDCConfig{
			IssuerURL:   "http://localhost:5556",
			ClientID:    "bifrost-client",
			DatabaseURL: databaseURL,
		}
		authPlugin, err := auth.NewAuthPluginWithDB(oidcConfig, sharedDB)
		if err != nil {
			log.Fatalf("Failed to create auth plugin: %v", err)
		}
		loadedPlugins = append(loadedPlugins, authPlugin)
		log.Println("Auth plugin initialized for API request validation")

		// Initialize secure logging plugin with shared database
		if store.ClientConfig.EnableLogging {
			secureLoggingPlugin := logging.NewSecureLoggingPlugin(sharedDB)
			loadedPlugins = append(loadedPlugins, secureLoggingPlugin)
			log.Println("Secure logging plugin initialized with PostgreSQL")
		}
	} else {
		log.Println("DATABASE_URL not set, skipping database-dependent plugins")
	}

	client, err := bifrost.Init(schemas.BifrostConfig{
		Account:            account,
		InitialPoolSize:    store.ClientConfig.InitialPoolSize,
		DropExcessRequests: store.ClientConfig.DropExcessRequests,
		Plugins:            loadedPlugins,
		MCPConfig:          store.MCPConfig,
		Logger:             logger,
	})
	if err != nil {
		log.Fatalf("failed to initialize bifrost: %v", err)
	}

	store.SetBifrostClient(client)

	// Initialize handlers
	providerHandler := handlers.NewProviderHandler(store, client, logger)
	completionHandler := handlers.NewCompletionHandler(client, logger)
	mcpHandler := handlers.NewMCPHandler(client, logger, store)
	integrationHandler := handlers.NewIntegrationHandler(client)
	configHandler := handlers.NewConfigHandler(client, logger, store, configPath)
	
	// Create auth handler with shared database if available
	var authHandler *auth.AuthHandler
	if sharedDB != nil {
		authHandler = auth.NewAuthHandlerWithDB(store, sharedDB)
		log.Println("Auth handler configured with shared database access")
	} else {
		authHandler = auth.NewAuthHandler(store)
	}
	
	// Create logging handler if database is available
	var loggingHandler *logging.LoggingHandler
	if sharedDB != nil {
		loggingHandler = logging.NewLoggingHandler(sharedDB)
		log.Println("Logging handler configured with shared database access")
	}

	// Note: WebSocket logging handlers removed in favor of secure PostgreSQL logging

	r := router.New()

	// Register all handler routes FIRST (API routes take precedence)
	providerHandler.RegisterRoutes(r)
	completionHandler.RegisterRoutes(r)
	mcpHandler.RegisterRoutes(r)
	integrationHandler.RegisterRoutes(r)
	configHandler.RegisterRoutes(r)

	// Register authentication routes
	authHandler.RegisterRoutes(r)
	
	// Register logging routes if available
	if loggingHandler != nil {
		loggingHandler.RegisterRoutes(r)
	}

	// Add UI routes - serve the local index.html (these should be LAST)
	r.GET("/", uiHandler)
	// Use a more specific pattern to avoid catching API routes
	r.GET("/ui/{filepath:*}", uiHandler)
	r.GET("/app/{filepath:*}", uiHandler)
	r.GET("/static/{filepath:*}", uiHandler)

	r.NotFound = func(ctx *fasthttp.RequestCtx) {
		handlers.SendError(ctx, fasthttp.StatusNotFound, "Route not found: "+string(ctx.Path()), logger)
	}

	// Apply CORS middleware to all routes
	corsHandler := corsMiddleware(r.Handler)

	log.Printf("Successfully started bifrost. Serving UI on http://localhost:%s", port)
	if err := fasthttp.ListenAndServe(":"+port, corsHandler); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}

	client.Cleanup()
}
