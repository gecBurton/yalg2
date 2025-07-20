package logging

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// User represents a user for testing (compatible with auth.User)
type User struct {
	ID                   uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Sub                  string    `json:"sub" gorm:"uniqueIndex;not null"`
	Email                string    `json:"email"`
	Name                 string    `json:"name"`
	MaxRequestsPerMinute int       `json:"max_requests_per_minute" gorm:"default:60"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// setupTestDB creates a PostgreSQL test database connection
func setupTestDB(t *testing.T) *gorm.DB {
	// Use the same PostgreSQL connection as in docker-compose
	dsn := "host=localhost user=bifrost password=bifrost123 dbname=bifrost port=5432 sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Skipf("Failed to connect to test database (PostgreSQL may not be running): %v", err)
	}

	// Clean up existing data (ignore errors if tables don't exist)
	db.Exec("TRUNCATE TABLE log_entries CASCADE")
	db.Exec("TRUNCATE TABLE users CASCADE")

	// Auto-migrate the real models (User and LogEntry)
	err = db.AutoMigrate(&User{}, &LogEntry{})
	if err != nil {
		t.Fatalf("Failed to migrate test database: %v", err)
	}

	return db
}

func TestNewSecureLoggingPlugin(t *testing.T) {
	db := setupTestDB(t)
	plugin := NewSecureLoggingPlugin(db)

	if plugin == nil {
		t.Fatal("Expected plugin to be created")
	}

	if plugin.GetName() != "SecureLoggingPlugin" {
		t.Errorf("Expected plugin name 'SecureLoggingPlugin', got '%s'", plugin.GetName())
	}

	if plugin.db != db {
		t.Error("Expected database to be set")
	}
}

func TestNewSecureLoggingPlugin_NilDB(t *testing.T) {
	plugin := NewSecureLoggingPlugin(nil)

	if plugin == nil {
		t.Fatal("Expected plugin to be created even with nil db")
	}

	if plugin.db != nil {
		t.Error("Expected database to be nil")
	}
}

func TestPreHook(t *testing.T) {
	db := setupTestDB(t)
	plugin := NewSecureLoggingPlugin(db)

	ctx := context.Background()
	req := &schemas.BifrostRequest{
		Model: "gpt-4",
	}

	result, shortCircuit, err := plugin.PreHook(&ctx, req)

	// Test return values
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if shortCircuit != nil {
		t.Error("Expected no short circuit")
	}
	if result != req {
		t.Error("Expected request to be returned unchanged")
	}

	// Test context values
	startTime := ctx.Value("request_start_time")
	if startTime == nil {
		t.Error("Expected request_start_time to be set in context")
	}

	requestID := ctx.Value("request_id")
	if requestID == nil {
		t.Error("Expected request_id to be set in context")
	}

	// Verify request ID format
	if reqID, ok := requestID.(string); ok {
		if len(reqID) < 10 {
			t.Error("Expected request ID to be longer")
		}
		if reqID[len(reqID)-5:] != "gpt-4" {
			t.Error("Expected request ID to end with model name")
		}
	} else {
		t.Error("Expected request ID to be string")
	}
}

func TestPostHook_NoDatabase(t *testing.T) {
	plugin := NewSecureLoggingPlugin(nil)

	ctx := context.Background()
	response := &schemas.BifrostResponse{}
	bifrostErr := &schemas.BifrostError{}

	result, err, pluginErr := plugin.PostHook(&ctx, response, bifrostErr)

	if pluginErr != nil {
		t.Errorf("Expected no plugin error, got: %v", pluginErr)
	}
	if result != response {
		t.Error("Expected response to be returned unchanged")
	}
	if err != bifrostErr {
		t.Error("Expected bifrost error to be returned unchanged")
	}
}

func TestPostHook_SuccessfulResponse(t *testing.T) {
	db := setupTestDB(t)
	plugin := NewSecureLoggingPlugin(db)

	// Create a test user first
	userID := uuid.New()
	user := &User{
		ID:   userID,
		Sub:  "successful-test-user",
		Name: "Successful Test User",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Set up context with required values
	ctx := context.Background()
	startTime := time.Now().Add(-100 * time.Millisecond)
	ctx = context.WithValue(ctx, "request_start_time", startTime)
	ctx = context.WithValue(ctx, "request_id", "test-request-123")
	ctx = context.WithValue(ctx, "user_id", userID)

	bifrostReq := &schemas.BifrostRequest{
		Model:    "gpt-4",
		Provider: "openai",
	}
	ctx = context.WithValue(ctx, "bifrost_request", bifrostReq)

	response := &schemas.BifrostResponse{
		Usage: &schemas.LLMUsage{
			TotalTokens: 150,
		},
	}

	result, err, pluginErr := plugin.PostHook(&ctx, response, nil)

	// Test return values
	if pluginErr != nil {
		t.Errorf("Expected no plugin error, got: %v", pluginErr)
	}
	if result != response {
		t.Error("Expected response to be returned unchanged")
	}
	if err != nil {
		t.Error("Expected no bifrost error")
	}

	// Verify log entry was created
	var logEntry LogEntry
	dbErr := db.Where("request_id = ?", "test-request-123").First(&logEntry).Error
	if dbErr != nil {
		t.Fatalf("Expected log entry to be created: %v", dbErr)
	}

	// Verify log entry fields
	if logEntry.UserID == nil || *logEntry.UserID != userID {
		t.Errorf("Expected user ID %s, got %v", userID, logEntry.UserID)
	}
	if logEntry.RequestID != "test-request-123" {
		t.Errorf("Expected request ID 'test-request-123', got '%s'", logEntry.RequestID)
	}
	if logEntry.ModelProvider != "openai" {
		t.Errorf("Expected provider 'openai', got '%s'", logEntry.ModelProvider)
	}
	if logEntry.ModelName != "gpt-4" {
		t.Errorf("Expected model 'gpt-4', got '%s'", logEntry.ModelName)
	}
	if logEntry.TokensUsed != 150 {
		t.Errorf("Expected tokens 150, got %d", logEntry.TokensUsed)
	}
	if logEntry.StatusCode != 200 {
		t.Errorf("Expected status code 200, got %d", logEntry.StatusCode)
	}
	if logEntry.ResponseTimeMs < 50 || logEntry.ResponseTimeMs > 200 {
		t.Errorf("Expected response time around 100ms, got %d", logEntry.ResponseTimeMs)
	}
	if logEntry.RequestType != "chat" {
		t.Errorf("Expected request type 'chat', got '%s'", logEntry.RequestType)
	}
}

func TestPostHook_ErrorResponse(t *testing.T) {
	db := setupTestDB(t)
	plugin := NewSecureLoggingPlugin(db)

	// Create a test user first
	userID := uuid.New()
	user := &User{
		ID:   userID,
		Sub:  "error-test-user",
		Name: "Error Test User",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Set up context with required values
	ctx := context.Background()
	startTime := time.Now().Add(-50 * time.Millisecond)
	ctx = context.WithValue(ctx, "request_start_time", startTime)
	ctx = context.WithValue(ctx, "request_id", "test-error-456")
	ctx = context.WithValue(ctx, "user_id", userID)

	statusCode := 429
	bifrostErr := &schemas.BifrostError{
		StatusCode: &statusCode,
		Error: schemas.ErrorField{
			Message: "Rate limit exceeded",
		},
	}

	result, err, pluginErr := plugin.PostHook(&ctx, nil, bifrostErr)

	// Test return values
	if pluginErr != nil {
		t.Errorf("Expected no plugin error, got: %v", pluginErr)
	}
	if result != nil {
		t.Error("Expected nil response")
	}
	if err != bifrostErr {
		t.Error("Expected bifrost error to be returned unchanged")
	}

	// Verify log entry was created
	var logEntry LogEntry
	dbErr := db.Where("request_id = ?", "test-error-456").First(&logEntry).Error
	if dbErr != nil {
		t.Fatalf("Expected log entry to be created: %v", dbErr)
	}

	// Verify error log entry fields
	if logEntry.StatusCode != 429 {
		t.Errorf("Expected status code 429, got %d", logEntry.StatusCode)
	}
	if logEntry.ErrorMessage != "Rate limit exceeded" {
		t.Errorf("Expected error message 'Rate limit exceeded', got '%s'", logEntry.ErrorMessage)
	}
	if logEntry.TokensUsed != 0 {
		t.Errorf("Expected tokens 0 for error, got %d", logEntry.TokensUsed)
	}
}

func TestPostHook_ErrorWithoutStatusCode(t *testing.T) {
	db := setupTestDB(t)
	plugin := NewSecureLoggingPlugin(db)

	// Set up context with required values
	ctx := context.Background()
	ctx = context.WithValue(ctx, "request_start_time", time.Now())
	ctx = context.WithValue(ctx, "request_id", "test-error-500")

	bifrostErr := &schemas.BifrostError{
		Error: schemas.ErrorField{
			Message: "Internal error",
		},
	}

	plugin.PostHook(&ctx, nil, bifrostErr)

	// Verify log entry was created with default 500 status
	var logEntry LogEntry
	dbErr := db.Where("request_id = ?", "test-error-500").First(&logEntry).Error
	if dbErr != nil {
		t.Fatalf("Expected log entry to be created: %v", dbErr)
	}

	if logEntry.StatusCode != 500 {
		t.Errorf("Expected default status code 500, got %d", logEntry.StatusCode)
	}
}

func TestPostHook_NoUserContext(t *testing.T) {
	db := setupTestDB(t)
	plugin := NewSecureLoggingPlugin(db)

	// Set up context without user_id
	ctx := context.Background()
	ctx = context.WithValue(ctx, "request_start_time", time.Now())
	ctx = context.WithValue(ctx, "request_id", "test-no-user")

	response := &schemas.BifrostResponse{}

	plugin.PostHook(&ctx, response, nil)

	// Verify log entry was created without user ID
	var logEntry LogEntry
	dbErr := db.Where("request_id = ?", "test-no-user").First(&logEntry).Error
	if dbErr != nil {
		t.Fatalf("Expected log entry to be created: %v", dbErr)
	}

	if logEntry.UserID != nil {
		t.Error("Expected user ID to be nil when no user context")
	}
}

func TestPostHook_InvalidUserIDType(t *testing.T) {
	db := setupTestDB(t)
	plugin := NewSecureLoggingPlugin(db)

	// Set up context with invalid user_id type
	ctx := context.Background()
	ctx = context.WithValue(ctx, "request_start_time", time.Now())
	ctx = context.WithValue(ctx, "request_id", "test-invalid-user")
	ctx = context.WithValue(ctx, "user_id", "invalid-string-id") // Wrong type

	response := &schemas.BifrostResponse{}

	plugin.PostHook(&ctx, response, nil)

	// Verify log entry was created without user ID
	var logEntry LogEntry
	dbErr := db.Where("request_id = ?", "test-invalid-user").First(&logEntry).Error
	if dbErr != nil {
		t.Fatalf("Expected log entry to be created: %v", dbErr)
	}

	if logEntry.UserID != nil {
		t.Error("Expected user ID to be nil when invalid user context type")
	}
}

func TestGetRecentCallsForUser(t *testing.T) {
	db := setupTestDB(t)
	plugin := NewSecureLoggingPlugin(db)

	// Create a test user
	userID := uuid.New()
	user := &User{
		ID:    userID,
		Sub:   "test-user",
		Email: "test@example.com",
		Name:  "Test User",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create some log entries for this user
	for i := 0; i < 5; i++ {
		logEntry := &LogEntry{
			ID:            uuid.New(),
			UserID:        &userID,
			RequestID:     fmt.Sprintf("request-%d", i),
			ModelProvider: "openai",
			ModelName:     "gpt-4",
			TokensUsed:    100 + i*10,
			StatusCode:    200,
			CreatedAt:     time.Now().Add(-time.Duration(i) * time.Hour),
		}
		if err := db.Create(logEntry).Error; err != nil {
			t.Fatalf("Failed to create test log entry: %v", err)
		}
	}

	// Create log entries for another user (should not be returned)
	otherUserID := uuid.New()
	otherUser := &User{
		ID:    otherUserID,
		Sub:   "other-user",
		Email: "other@example.com",
		Name:  "Other User",
	}
	if err := db.Create(otherUser).Error; err != nil {
		t.Fatalf("Failed to create other test user: %v", err)
	}

	for i := 0; i < 3; i++ {
		logEntry := &LogEntry{
			ID:            uuid.New(),
			UserID:        &otherUserID,
			RequestID:     fmt.Sprintf("other-request-%d", i),
			ModelProvider: "anthropic",
			ModelName:     "claude-3",
			TokensUsed:    50 + i*5,
			StatusCode:    200,
			CreatedAt:     time.Now().Add(-time.Duration(i) * time.Hour),
		}
		if err := db.Create(logEntry).Error; err != nil {
			t.Fatalf("Failed to create other user log entry: %v", err)
		}
	}

	// Test getting recent calls
	entries, err := plugin.GetRecentCallsForUser(userID, 3)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify results
	if len(entries) != 3 {
		t.Errorf("Expected 3 entries, got %d", len(entries))
	}

	// Verify entries are for the correct user and ordered by creation time (newest first)
	for i, entry := range entries {
		if entry.UserID == nil || *entry.UserID != userID {
			t.Errorf("Entry %d: expected user ID %s, got %v", i, userID, entry.UserID)
		}

		// Check that entries are ordered by creation time (newest first)
		if i > 0 {
			if entry.CreatedAt.After(entries[i-1].CreatedAt) {
				t.Errorf("Entry %d: entries not ordered by creation time desc", i)
			}
		}
	}

	// Verify most recent entry is request-0 (created most recently)
	if entries[0].RequestID != "request-0" {
		t.Errorf("Expected most recent entry to be 'request-0', got '%s'", entries[0].RequestID)
	}
}

func TestGetRecentCallsForUser_NoDatabase(t *testing.T) {
	plugin := NewSecureLoggingPlugin(nil)

	userID := uuid.New()
	entries, err := plugin.GetRecentCallsForUser(userID, 10)

	if err == nil {
		t.Error("Expected error when no database")
	}
	if entries != nil {
		t.Error("Expected nil entries when no database")
	}

	expectedError := "database not available"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

func TestGetRecentCallsForUser_NoEntries(t *testing.T) {
	db := setupTestDB(t)
	plugin := NewSecureLoggingPlugin(db)

	userID := uuid.New()
	entries, err := plugin.GetRecentCallsForUser(userID, 10)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("Expected 0 entries, got %d", len(entries))
	}
}

func TestCleanup(t *testing.T) {
	db := setupTestDB(t)
	plugin := NewSecureLoggingPlugin(db)

	err := plugin.Cleanup()
	if err != nil {
		t.Errorf("Expected no error during cleanup, got: %v", err)
	}
}

func TestCleanup_NoDatabase(t *testing.T) {
	plugin := NewSecureLoggingPlugin(nil)

	err := plugin.Cleanup()
	if err != nil {
		t.Errorf("Expected no error during cleanup with nil db, got: %v", err)
	}
}

// TestPostHook_CompleteWorkflow tests the complete workflow from PreHook to PostHook
func TestCompleteWorkflow(t *testing.T) {
	db := setupTestDB(t)
	plugin := NewSecureLoggingPlugin(db)

	// Create a test user
	userID := uuid.New()
	user := &User{
		ID:    userID,
		Sub:   "workflow-user",
		Email: "workflow@example.com",
		Name:  "Workflow User",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	ctx := context.Background()
	req := &schemas.BifrostRequest{
		Model:    "gpt-3.5-turbo",
		Provider: "openai",
	}

	// Step 1: PreHook
	result, shortCircuit, err := plugin.PreHook(&ctx, req)
	if err != nil || shortCircuit != nil || result != req {
		t.Fatal("PreHook failed")
	}

	// Add user context (simulating auth middleware)
	ctx = context.WithValue(ctx, "user_id", userID)
	ctx = context.WithValue(ctx, "bifrost_request", req)

	// Step 2: PostHook with successful response
	response := &schemas.BifrostResponse{
		Usage: &schemas.LLMUsage{
			TotalTokens: 250,
		},
	}

	resultResp, resultErr, pluginErr := plugin.PostHook(&ctx, response, nil)
	if pluginErr != nil || resultResp != response || resultErr != nil {
		t.Fatal("PostHook failed")
	}

	// Step 3: Verify log entry was created correctly
	requestID := ctx.Value("request_id").(string)
	var logEntry LogEntry
	dbErr := db.Where("request_id = ?", requestID).First(&logEntry).Error
	if dbErr != nil {
		t.Fatalf("Expected log entry to be created: %v", dbErr)
	}

	// Verify all fields
	if *logEntry.UserID != userID {
		t.Error("User ID mismatch")
	}
	if logEntry.ModelProvider != "openai" {
		t.Error("Provider mismatch")
	}
	if logEntry.ModelName != "gpt-3.5-turbo" {
		t.Error("Model name mismatch")
	}
	if logEntry.TokensUsed != 250 {
		t.Error("Token usage mismatch")
	}
	if logEntry.StatusCode != 200 {
		t.Error("Status code mismatch")
	}

	// Step 4: Test GetRecentCallsForUser
	entries, err := plugin.GetRecentCallsForUser(userID, 1)
	if err != nil {
		t.Fatalf("Failed to get recent calls: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(entries))
	}
	if entries[0].RequestID != requestID {
		t.Error("Request ID mismatch in recent calls")
	}
}