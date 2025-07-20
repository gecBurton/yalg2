package ratelimit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"bifrost-gov/internal/testutil"
	"bifrost-gov/plugins/auth"
	"bifrost-gov/plugins/logging"
	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
)

func TestNewRateLimitPlugin(t *testing.T) {
	db := testutil.SetupTestDB(t, &auth.User{}, &logging.LogEntry{})
	plugin := NewRateLimitPlugin(db)

	if plugin == nil {
		t.Fatal("Expected plugin to be created")
	}

	if plugin.GetName() != "RateLimitPlugin" {
		t.Errorf("Expected plugin name 'RateLimitPlugin', got '%s'", plugin.GetName())
	}
}

func TestPreHook_NoDatabase(t *testing.T) {
	plugin := NewRateLimitPlugin(nil)
	ctx := context.Background()
	req := &schemas.BifrostRequest{}

	result, shortCircuit, err := plugin.PreHook(&ctx, req)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if shortCircuit != nil {
		t.Error("Expected no short circuit when database is nil")
	}
	if result != req {
		t.Error("Expected request to be returned unchanged")
	}
}

func TestPreHook_NoUserContext(t *testing.T) {
	db := testutil.SetupTestDB(t, &auth.User{}, &logging.LogEntry{})
	plugin := NewRateLimitPlugin(db)
	ctx := context.Background()
	req := &schemas.BifrostRequest{}

	result, shortCircuit, err := plugin.PreHook(&ctx, req)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if shortCircuit != nil {
		t.Error("Expected no short circuit when no user context")
	}
	if result != req {
		t.Error("Expected request to be returned unchanged")
	}
}

func TestPreHook_UserNotFound(t *testing.T) {
	db := testutil.SetupTestDB(t, &auth.User{}, &logging.LogEntry{})
	plugin := NewRateLimitPlugin(db)
	nonExistentUserID := uuid.New()
	ctx := context.WithValue(context.Background(), "user_id", nonExistentUserID)
	req := &schemas.BifrostRequest{}

	result, shortCircuit, err := plugin.PreHook(&ctx, req)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if shortCircuit != nil {
		t.Error("Expected no short circuit when user not found")
	}
	if result != req {
		t.Error("Expected request to be returned unchanged")
	}
}

func TestPreHook_WithinRateLimit(t *testing.T) {
	db := testutil.SetupTestDB(t, &auth.User{}, &logging.LogEntry{})
	plugin := NewRateLimitPlugin(db)

	// Create a test user with rate limit of 10 requests per minute
	userID := uuid.New()
	user := &auth.User{
		ID:                   userID,
		Sub:                  "test-user",
		Email:                "test@example.com",
		Name:                 "Test User",
		MaxRequestsPerMinute: 10,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create 5 log entries in the last minute
	for i := 0; i < 5; i++ {
		logEntry := &logging.LogEntry{
			ID:           uuid.New(),
			UserID:       &userID,
			RequestID:    fmt.Sprintf("test-request-%d", i),
			TokensUsed:   10,
			StatusCode:   200,
			RequestType:  "chat",
			CreatedAt:    time.Now().Add(-30 * time.Second),
		}
		if err := db.Create(logEntry).Error; err != nil {
			t.Fatalf("Failed to create test log entry: %v", err)
		}
	}

	ctx := context.WithValue(context.Background(), "user_id", userID)
	req := &schemas.BifrostRequest{}

	result, shortCircuit, err := plugin.PreHook(&ctx, req)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if shortCircuit != nil {
		t.Error("Expected no short circuit when within rate limit")
	}
	if result != req {
		t.Error("Expected request to be returned unchanged")
	}
}

func TestPreHook_ExceedsRateLimit(t *testing.T) {
	db := testutil.SetupTestDB(t, &auth.User{}, &logging.LogEntry{})
	plugin := NewRateLimitPlugin(db)

	// Create a test user with rate limit of 5 requests per minute
	userID := uuid.New()
	user := &auth.User{
		ID:                   userID,
		Sub:                  "test-user",
		Email:                "test@example.com",
		Name:                 "Test User",
		MaxRequestsPerMinute: 5,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create 5 log entries in the last minute (exactly at the limit)
	for i := 0; i < 5; i++ {
		logEntry := &logging.LogEntry{
			ID:           uuid.New(),
			UserID:       &userID,
			RequestID:    fmt.Sprintf("limit-request-%d", i),
			TokensUsed:   10,
			StatusCode:   200,
			RequestType:  "chat",
			CreatedAt:    time.Now().Add(-30 * time.Second),
		}
		if err := db.Create(logEntry).Error; err != nil {
			t.Fatalf("Failed to create test log entry: %v", err)
		}
	}

	ctx := context.WithValue(context.Background(), "user_id", userID)
	req := &schemas.BifrostRequest{}

	result, shortCircuit, err := plugin.PreHook(&ctx, req)

	if err == nil {
		t.Error("Expected rate limit error")
	}
	if shortCircuit != nil {
		t.Error("Expected no short circuit when returning error")
	}
	if result != req {
		t.Error("Expected request to be returned unchanged")
	}

	expectedError := "rate limit exceeded: 5 requests in the last minute (limit: 5)"
	if err.Error() != expectedError {
		t.Errorf("Expected error message '%s', got '%s'", expectedError, err.Error())
	}
}

func TestPreHook_OldRequestsIgnored(t *testing.T) {
	db := testutil.SetupTestDB(t, &auth.User{}, &logging.LogEntry{})
	plugin := NewRateLimitPlugin(db)

	// Create a test user with rate limit of 5 requests per minute
	userID := uuid.New()
	user := &auth.User{
		ID:                   userID,
		Sub:                  "test-user",
		Email:                "test@example.com",
		Name:                 "Test User",
		MaxRequestsPerMinute: 5,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create 10 log entries older than 1 minute (should be ignored)
	for i := 0; i < 10; i++ {
		logEntry := &logging.LogEntry{
			ID:           uuid.New(),
			UserID:       &userID,
			RequestID:    fmt.Sprintf("old-request-%d", i),
			TokensUsed:   10,
			StatusCode:   200,
			RequestType:  "chat",
			CreatedAt:    time.Now().Add(-2 * time.Minute),
		}
		if err := db.Create(logEntry).Error; err != nil {
			t.Fatalf("Failed to create test log entry: %v", err)
		}
	}

	// Create 2 recent log entries (within the limit)
	for i := 0; i < 2; i++ {
		logEntry := &logging.LogEntry{
			ID:           uuid.New(),
			UserID:       &userID,
			RequestID:    fmt.Sprintf("recent-request-%d", i),
			TokensUsed:   10,
			StatusCode:   200,
			RequestType:  "chat",
			CreatedAt:    time.Now().Add(-30 * time.Second),
		}
		if err := db.Create(logEntry).Error; err != nil {
			t.Fatalf("Failed to create test log entry: %v", err)
		}
	}

	ctx := context.WithValue(context.Background(), "user_id", userID)
	req := &schemas.BifrostRequest{}

	result, shortCircuit, err := plugin.PreHook(&ctx, req)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if shortCircuit != nil {
		t.Error("Expected no short circuit when within rate limit")
	}
	if result != req {
		t.Error("Expected request to be returned unchanged")
	}
}

func TestGetUserRateLimit(t *testing.T) {
	db := testutil.SetupTestDB(t, &auth.User{}, &logging.LogEntry{})
	plugin := NewRateLimitPlugin(db)

	// Create a test user
	userID := uuid.New()
	user := &auth.User{
		ID:                   userID,
		Sub:                  "test-user",
		Email:                "test@example.com",
		Name:                 "Test User",
		MaxRequestsPerMinute: 42,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	limit, err := plugin.GetUserRateLimit(userID)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if limit != 42 {
		t.Errorf("Expected rate limit 42, got %d", limit)
	}
}

func TestGetUserRequestCount(t *testing.T) {
	db := testutil.SetupTestDB(t, &auth.User{}, &logging.LogEntry{})
	plugin := NewRateLimitPlugin(db)

	// Create a test user first
	userID := uuid.New()
	user := &auth.User{
		ID:                   userID,
		Sub:                  "count-test-user",
		Email:                "count@example.com",
		Name:                 "Count Test User",
		MaxRequestsPerMinute: 10,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create 3 log entries in the last minute
	for i := 0; i < 3; i++ {
		logEntry := &logging.LogEntry{
			ID:           uuid.New(),
			UserID:       &userID,
			RequestID:    fmt.Sprintf("count-request-%d", i),
			TokensUsed:   10,
			StatusCode:   200,
			RequestType:  "chat",
			CreatedAt:    time.Now().Add(-30 * time.Second),
		}
		if err := db.Create(logEntry).Error; err != nil {
			t.Fatalf("Failed to create test log entry: %v", err)
		}
	}

	// Create 2 log entries older than 1 minute (should be ignored)
	for i := 0; i < 2; i++ {
		logEntry := &logging.LogEntry{
			ID:           uuid.New(),
			UserID:       &userID,
			RequestID:    fmt.Sprintf("old-count-request-%d", i),
			TokensUsed:   10,
			StatusCode:   200,
			RequestType:  "chat",
			CreatedAt:    time.Now().Add(-2 * time.Minute),
		}
		if err := db.Create(logEntry).Error; err != nil {
			t.Fatalf("Failed to create test log entry: %v", err)
		}
	}

	count, err := plugin.GetUserRequestCount(userID)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if count != 3 {
		t.Errorf("Expected request count 3, got %d", count)
	}
}

func TestUpdateUserRateLimit(t *testing.T) {
	db := testutil.SetupTestDB(t, &auth.User{}, &logging.LogEntry{})
	plugin := NewRateLimitPlugin(db)

	// Create a test user
	userID := uuid.New()
	user := &auth.User{
		ID:                   userID,
		Sub:                  "test-user",
		Email:                "test@example.com",
		Name:                 "Test User",
		MaxRequestsPerMinute: 10,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Update the rate limit
	err := plugin.UpdateUserRateLimit(userID, 20)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Verify the update
	limit, err := plugin.GetUserRateLimit(userID)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if limit != 20 {
		t.Errorf("Expected updated rate limit 20, got %d", limit)
	}
}

func TestPostHook(t *testing.T) {
	db := testutil.SetupTestDB(t, &auth.User{}, &logging.LogEntry{})
	plugin := NewRateLimitPlugin(db)

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

func TestCleanup(t *testing.T) {
	db := testutil.SetupTestDB(t, &auth.User{}, &logging.LogEntry{})
	plugin := NewRateLimitPlugin(db)

	err := plugin.Cleanup()
	if err != nil {
		t.Errorf("Expected no error during cleanup, got: %v", err)
	}
}