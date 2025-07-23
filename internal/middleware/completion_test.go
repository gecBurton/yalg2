package middleware

import (
	"testing"

	"bifrost-gov/internal/database"
	"bifrost-gov/internal/testutil"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/bifrost-http/handlers"
	"github.com/valyala/fasthttp"
)

func TestNewLoggedCompletionHandler(t *testing.T) {
	db := testutil.SetupTestDB(t, &database.User{}, &database.LogEntry{})
	logger, err := database.NewPostgresLogger(db, schemas.LogLevelInfo)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Create a mock completion handler (we can't easily create a real one without full Bifrost setup)
	completionHandler := &handlers.CompletionHandler{}

	loggedHandler := NewLoggedCompletionHandler(completionHandler, logger)
	
	if loggedHandler == nil {
		t.Fatal("Expected logged completion handler to be created")
	}
	if loggedHandler.handler != completionHandler {
		t.Error("Expected completion handler to be set correctly")
	}
	if loggedHandler.logger != logger {
		t.Error("Expected logger to be set correctly")
	}
}

func TestLoggedCompletionHandler_RegisterRoutes(t *testing.T) {
	db := testutil.SetupTestDB(t, &database.User{}, &database.LogEntry{})
	logger, err := database.NewPostgresLogger(db, schemas.LogLevelInfo)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	completionHandler := &handlers.CompletionHandler{}
	loggedHandler := NewLoggedCompletionHandler(completionHandler, logger)
	
	r := router.New()
	loggedHandler.RegisterRoutes(r)

	// Test that routes are registered
	routes := []string{"/v1/chat/completions", "/v1/text/completions"}
	for _, route := range routes {
		h, _ := r.Lookup("POST", route, nil)
		if h == nil {
			t.Errorf("Expected route %s to be registered", route)
		}
	}
}

func TestLoggedCompletionHandler_ExtractRequestInfo(t *testing.T) {
	db := testutil.SetupTestDB(t, &database.User{}, &database.LogEntry{})
	logger, err := database.NewPostgresLogger(db, schemas.LogLevelInfo)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	completionHandler := &handlers.CompletionHandler{}
	loggedHandler := NewLoggedCompletionHandler(completionHandler, logger)

	// Test with valid JSON request body
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetBody([]byte(`{"model": "openai/gpt-4", "messages": [{"role": "user", "content": "Hello"}]}`))
	
	userID, model, provider := loggedHandler.extractRequestInfo(ctx)
	
	// Should return nil UUID since no user_id is set in context
	if userID.String() != "00000000-0000-0000-0000-000000000000" {
		t.Errorf("Expected nil UUID, got %s", userID)
	}
	
	if model != "gpt-4" {
		t.Errorf("Expected model 'gpt-4', got '%s'", model)
	}
	
	if provider != "openai" {
		t.Errorf("Expected provider 'openai', got '%s'", provider)
	}
}

func TestLoggedCompletionHandler_IsStreamingRequest(t *testing.T) {
	db := testutil.SetupTestDB(t, &database.User{}, &database.LogEntry{})
	logger, err := database.NewPostgresLogger(db, schemas.LogLevelInfo)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	completionHandler := &handlers.CompletionHandler{}
	loggedHandler := NewLoggedCompletionHandler(completionHandler, logger)

	// Test streaming request
	streamingBody := []byte(`{"model": "gpt-4", "stream": true, "messages": []}`)
	if !loggedHandler.isStreamingRequest(streamingBody) {
		t.Error("Expected streaming request to be detected")
	}

	// Test non-streaming request
	nonStreamingBody := []byte(`{"model": "gpt-4", "stream": false, "messages": []}`)
	if loggedHandler.isStreamingRequest(nonStreamingBody) {
		t.Error("Expected non-streaming request to be detected")
	}

	// Test request without stream field
	noStreamBody := []byte(`{"model": "gpt-4", "messages": []}`)
	if loggedHandler.isStreamingRequest(noStreamBody) {
		t.Error("Expected non-streaming request when stream field is missing")
	}
}

func TestLoggedCompletionHandler_ExtractTokenUsage(t *testing.T) {
	db := testutil.SetupTestDB(t, &database.User{}, &database.LogEntry{})
	logger, err := database.NewPostgresLogger(db, schemas.LogLevelInfo)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	completionHandler := &handlers.CompletionHandler{}
	loggedHandler := NewLoggedCompletionHandler(completionHandler, logger)

	// Test response with token usage
	responseBody := []byte(`{"choices": [{"message": {"content": "Hello"}}], "usage": {"total_tokens": 150, "prompt_tokens": 50, "completion_tokens": 100}}`)
	tokens := loggedHandler.extractTokenUsage(responseBody)
	
	if tokens != 150 {
		t.Errorf("Expected 150 tokens, got %d", tokens)
	}

	// Test response without usage
	noUsageBody := []byte(`{"choices": [{"message": {"content": "Hello"}}]}`)
	tokens = loggedHandler.extractTokenUsage(noUsageBody)
	
	if tokens != 0 {
		t.Errorf("Expected 0 tokens, got %d", tokens)
	}
}

func TestLoggedCompletionHandler_ExtractErrorMessage(t *testing.T) {
	db := testutil.SetupTestDB(t, &database.User{}, &database.LogEntry{})
	logger, err := database.NewPostgresLogger(db, schemas.LogLevelInfo)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	completionHandler := &handlers.CompletionHandler{}
	loggedHandler := NewLoggedCompletionHandler(completionHandler, logger)

	// Test error response with string error
	errorBody := []byte(`{"error": "Rate limit exceeded"}`)
	errorMsg := loggedHandler.extractErrorMessage(errorBody)
	
	if errorMsg != "Rate limit exceeded" {
		t.Errorf("Expected 'Rate limit exceeded', got '%s'", errorMsg)
	}

	// Test error response with object error
	objectErrorBody := []byte(`{"error": {"message": "Invalid API key", "type": "auth_error"}}`)
	errorMsg = loggedHandler.extractErrorMessage(objectErrorBody)
	
	if errorMsg != "Invalid API key" {
		t.Errorf("Expected 'Invalid API key', got '%s'", errorMsg)
	}

	// Test success response
	successBody := []byte(`{"choices": [{"message": {"content": "Hello"}}]}`)
	errorMsg = loggedHandler.extractErrorMessage(successBody)
	
	if errorMsg != "" {
		t.Errorf("Expected empty error message, got '%s'", errorMsg)
	}

	// Test empty body
	errorMsg = loggedHandler.extractErrorMessage([]byte{})
	
	if errorMsg != "" {
		t.Errorf("Expected empty error message for empty body, got '%s'", errorMsg)
	}
}