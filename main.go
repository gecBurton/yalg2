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
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"time"

	"mime"
	"os"
	"path"
	"path/filepath"
	"strings"

	"context"

	"bifrost-gov/internal/database"
	webHandlers "bifrost-gov/internal/handlers"
	"bifrost-gov/internal/middleware"
	"bifrost-gov/plugins/ratelimit"

	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	bifrost "github.com/maximhq/bifrost/core"
	schemas "github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/bifrost-http/handlers"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
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

// LoggedCompletionHandler wraps Bifrost handlers with enhanced PostgreSQL logging
type LoggedCompletionHandler struct {
	handler *handlers.CompletionHandler
	logger  *database.PostgresLogger
}

// RegisterRoutes wraps the original handler routes with logging
func (l *LoggedCompletionHandler) RegisterRoutes(r *router.Router) {
	// Get the original routes by registering to a temporary router
	tempRouter := router.New()
	l.handler.RegisterRoutes(tempRouter)

	// Wrap the handlers with logging
	r.POST("/v1/chat/completions", l.wrapWithLogging(tempRouter, "/v1/chat/completions", "chat"))
	r.POST("/v1/text/completions", l.wrapWithLogging(tempRouter, "/v1/text/completions", "completion"))
}

// wrapWithLogging creates a logging wrapper for any handler
func (l *LoggedCompletionHandler) wrapWithLogging(tempRouter *router.Router, path, requestType string) fasthttp.RequestHandler {
	// Get the original handler
	originalHandler, _ := tempRouter.Lookup("POST", path, nil)

	return func(ctx *fasthttp.RequestCtx) {
		startTime := time.Now()
		requestID := fmt.Sprintf("req-%d", time.Now().UnixNano())

		// Extract request info for logging
		userID, model, provider := l.extractRequestInfo(ctx)
		
		// Capture request body and other context
		requestBody := ctx.PostBody()
		clientIP := string(ctx.Request.Header.Peek("X-Forwarded-For"))
		if clientIP == "" {
			clientIP = ctx.RemoteIP().String()
		}
		userAgent := string(ctx.Request.Header.Peek("User-Agent"))
		
		// Check if this is a streaming request
		isStreaming := l.isStreamingRequest(requestBody)
		
		// Set context values for potential use by Bifrost
		ctx.SetUserValue("request_id", requestID)
		ctx.SetUserValue("request_start_time", startTime)
		ctx.SetUserValue("client_ip", clientIP)
		ctx.SetUserValue("user_agent", userAgent)
		ctx.SetUserValue("request_body", requestBody)
		ctx.SetUserValue("is_streaming", isStreaming)

		// Log streaming start if applicable
		if isStreaming {
			l.logger.LogStreamingUpdate(userID, requestID, "start", "")
		}

		// Call original handler (GitHub plugin will capture detailed logs automatically)
		originalHandler(ctx)

		// Extract response info for our PostgreSQL logging
		statusCode := ctx.Response.StatusCode()
		errorMessage := l.extractErrorMessage(ctx.Response.Body())
		responseTime := int(time.Since(startTime).Milliseconds())
		responseBody := ctx.Response.Body()
		
		// Extract token usage from response if available
		tokensUsed := l.extractTokenUsage(responseBody)

		// Use the enhanced LogAPIRequestWithContext method for our PostgreSQL logs
		l.logger.LogAPIRequestWithContext(userID, requestType, model, provider, statusCode, errorMessage, responseTime, tokensUsed, requestID, clientIP, userAgent, isStreaming, requestBody, responseBody)
	}
}

// extractRequestInfo extracts user ID and model info from request
func (l *LoggedCompletionHandler) extractRequestInfo(ctx *fasthttp.RequestCtx) (uuid.UUID, string, string) {
	// Extract user ID from auth middleware
	userID := uuid.Nil
	if userIDValue := ctx.UserValue("user_id"); userIDValue != nil {
		if uid, ok := userIDValue.(uuid.UUID); ok {
			userID = uid
		}
	}

	// Parse model from request body
	model, provider := "unknown", "unknown"
	var requestBody map[string]interface{}
	if err := json.Unmarshal(ctx.PostBody(), &requestBody); err == nil {
		if modelStr, ok := requestBody["model"].(string); ok {
			if parts := strings.Split(modelStr, "/"); len(parts) >= 2 {
				provider, model = parts[0], parts[1]
			} else {
				model = modelStr
			}
		}
	}

	return userID, model, provider
}

// isStreamingRequest checks if the request is for streaming
func (l *LoggedCompletionHandler) isStreamingRequest(requestBody []byte) bool {
	var reqMap map[string]interface{}
	if err := json.Unmarshal(requestBody, &reqMap); err == nil {
		if stream, ok := reqMap["stream"].(bool); ok {
			return stream
		}
	}
	return false
}

// extractTokenUsage extracts token usage from response body
func (l *LoggedCompletionHandler) extractTokenUsage(responseBody []byte) int {
	var respMap map[string]interface{}
	if err := json.Unmarshal(responseBody, &respMap); err == nil {
		if usage, ok := respMap["usage"].(map[string]interface{}); ok {
			if total, ok := usage["total_tokens"].(float64); ok {
				return int(total)
			}
		}
	}
	return 0
}

// extractErrorMessage extracts error message from response body
func (l *LoggedCompletionHandler) extractErrorMessage(responseBody []byte) string {
	if len(responseBody) == 0 {
		return ""
	}

	var respMap map[string]interface{}
	if err := json.Unmarshal(responseBody, &respMap); err == nil {
		if errMsg, ok := respMap["error"].(string); ok {
			return errMsg
		}
		if errMap, ok := respMap["error"].(map[string]interface{}); ok {
			if msg, ok := errMap["message"].(string); ok {
				return msg
			}
		}
	}
	return ""
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
// 1. Loads environment variables from .env file
// 2. Initializes Prometheus collectors for monitoring
// 3. Reads and parses configuration from the specified config file
// 4. Initializes the Bifrost client with the configuration
// 5. Sets up HTTP routes for text and chat completions
// 6. Starts the HTTP server on the specified port
//
// The server exposes the following endpoints:
//   - POST /v1/text/completions: For text completion requests
//   - POST /v1/chat/completions: For chat completion requests
//   - GET /metrics: For Prometheus metrics
func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
		log.Printf("Continuing with existing environment variables...")
	} else {
		log.Println("Successfully loaded environment variables from .env file")
	}

	// Ensure app directory exists
	if err := os.MkdirAll(appDir, 0755); err != nil {
		log.Fatalf("failed to create app directory %s: %v", appDir, err)
	}

	// Derive paths from app-dir
	configPath := filepath.Join(appDir, "config.json")

	// Initialize high-performance configuration store with caching
	tempLogger := bifrost.NewDefaultLogger(schemas.LogLevelInfo)
	store, err := lib.NewConfigStore(tempLogger)
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

	// Initialize shared database connection (required)
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatalf("DATABASE_URL environment variable is required")
	}

	sharedDB, err := database.NewPostgresConnection(databaseURL)
	if err != nil {
		log.Fatalf("Failed to create database connection: %v", err)
	}
	log.Println("Shared database connection established")

	// Initialize authentication middleware
	authMiddleware, err := middleware.NewAuthMiddleware(middleware.DefaultAuthConfig(), sharedDB)
	if err != nil {
		log.Fatalf("Failed to create auth middleware: %v", err)
	}
	log.Println("Authentication middleware initialized")

	// Create custom PostgreSQL logger with enhanced features
	postgresLogger, err := database.NewPostgresLogger(sharedDB, schemas.LogLevelInfo)
	if err != nil {
		log.Fatalf("Failed to create PostgreSQL logger: %v", err)
	}
	
	// Start periodic cleanup (clean logs older than 30 days, run every 24 hours)
	postgresLogger.StartPeriodicCleanup(24*time.Hour, 30*24*time.Hour)
	log.Println("PostgreSQL logger initialized with async processing and cleanup")

	// Enhanced PostgreSQL logger now includes advanced LLMUsage tracking
	log.Println("PostgreSQL logger ready with advanced LLMUsage tracking")

	// Initialize rate limiting plugin with shared database
	rateLimitPlugin := ratelimit.NewRateLimitPlugin(sharedDB)
	loadedPlugins = append(loadedPlugins, rateLimitPlugin)
	log.Println("Rate limiting plugin initialized with PostgreSQL")

	client, err := bifrost.Init(schemas.BifrostConfig{
		Account:            account,
		InitialPoolSize:    store.ClientConfig.InitialPoolSize,
		DropExcessRequests: store.ClientConfig.DropExcessRequests,
		Plugins:            loadedPlugins,
		MCPConfig:          store.MCPConfig,
		Logger:             postgresLogger,
	})
	if err != nil {
		log.Fatalf("failed to initialize bifrost: %v", err)
	}

	store.SetBifrostClient(client)

	// Initialize handlers
	providerHandler := handlers.NewProviderHandler(store, client, postgresLogger)

	// Create standard completion handler (auth will be handled by middleware)
	completionHandler := handlers.NewCompletionHandler(client, postgresLogger)
	log.Println("Using standard completion handler with auth middleware")

	// Wrap completion handler with enhanced PostgreSQL logging
	loggedCompletionHandler := &LoggedCompletionHandler{
		handler: completionHandler,
		logger:  postgresLogger,
	}

	mcpHandler := handlers.NewMCPHandler(client, postgresLogger, store)
	integrationHandler := handlers.NewIntegrationHandler(client)
	configHandler := handlers.NewConfigHandler(client, postgresLogger, store, configPath)

	// Create web auth handler with shared database
	webAuthHandler, err := webHandlers.NewWebAuthHandler(store, sharedDB)
	if err != nil {
		log.Fatalf("Failed to create web auth handler: %v", err)
	}
	log.Println("Web auth handler configured with shared database access")

	// Create unified logging handler with PostgreSQL logger (includes basic + enhanced endpoints)
	loggingHandler := webHandlers.NewLoggingHandler(postgresLogger)
	log.Println("Unified logging handler configured with PostgreSQL logger (basic + enhanced endpoints)")

	// Note: WebSocket logging handlers removed in favor of secure PostgreSQL logging

	r := router.New()

	// Register all handler routes FIRST (API routes take precedence)
	providerHandler.RegisterRoutes(r)
	loggedCompletionHandler.RegisterRoutes(r)
	mcpHandler.RegisterRoutes(r)
	integrationHandler.RegisterRoutes(r)
	configHandler.RegisterRoutes(r)

	// Register web authentication routes
	webAuthHandler.RegisterRoutes(r)

	// Register unified logging routes (includes /metrics + /api/* endpoints)
	loggingHandler.RegisterRoutes(r)

	// Add UI routes - serve the local index.html (these should be LAST)
	r.GET("/", uiHandler)
	// Use a more specific pattern to avoid catching API routes
	r.GET("/ui/{filepath:*}", uiHandler)
	r.GET("/app/{filepath:*}", uiHandler)
	r.GET("/static/{filepath:*}", uiHandler)

	r.NotFound = func(ctx *fasthttp.RequestCtx) {
		handlers.SendError(ctx, fasthttp.StatusNotFound, "Route not found: "+string(ctx.Path()), postgresLogger)
	}

	// Apply CORS middleware to all routes
	corsHandler := corsMiddleware(r.Handler)

	// Apply authentication middleware to protected routes
	finalHandler := authMiddleware.Handler(corsHandler)

	log.Printf("Successfully started bifrost. Serving UI on http://localhost:%s", port)
	if err := fasthttp.ListenAndServe(":"+port, finalHandler); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}

	// Cleanup resources
	postgresLogger.Close()
	client.Cleanup()
}
