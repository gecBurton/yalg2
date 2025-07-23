package middleware

import (
	"encoding/json"
	"testing"
	"time"

	"bifrost-gov/internal/database"
	"bifrost-gov/internal/testutil"

	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/valyala/fasthttp"
)

func TestNewLoggingHandler(t *testing.T) {
	db := testutil.SetupTestDB(t, &database.User{}, &database.LogEntry{})
	logger, err := database.NewPostgresLogger(db, schemas.LogLevelInfo)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	handler := NewLoggingHandler(logger)
	if handler == nil {
		t.Fatal("Expected logging handler to be created")
	}
	if handler.logger != logger {
		t.Error("Expected logger to be set correctly")
	}
}

func TestLoggingHandler_RegisterRoutes(t *testing.T) {
	db := testutil.SetupTestDB(t, &database.User{}, &database.LogEntry{})
	logger, err := database.NewPostgresLogger(db, schemas.LogLevelInfo)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	handler := NewLoggingHandler(logger)
	r := router.New()
	handler.RegisterRoutes(r)

	// Test that routes are registered by checking if handlers exist
	routes := []string{"/metrics", "/api/enhanced-logs", "/api/token-usage", "/api/token-usage/summary"}
	for _, route := range routes {
		h, _ := r.Lookup("GET", route, nil)
		if h == nil {
			t.Errorf("Expected route %s to be registered", route)
		}
	}
}

func TestGetBasicMetrics_Unauthenticated(t *testing.T) {
	db := testutil.SetupTestDB(t, &database.User{}, &database.LogEntry{})
	logger, err := database.NewPostgresLogger(db, schemas.LogLevelInfo)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	handler := NewLoggingHandler(logger)

	ctx := &fasthttp.RequestCtx{}
	handler.getBasicMetrics(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	}

	var response map[string]string
	if err := json.Unmarshal(ctx.Response.Body(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response["error"] != "Not authenticated" {
		t.Errorf("Expected 'Not authenticated' error, got '%s'", response["error"])
	}
}

func TestGetBasicMetrics_Authenticated(t *testing.T) {
	db := testutil.SetupTestDB(t, &database.User{}, &database.LogEntry{})
	logger, err := database.NewPostgresLogger(db, schemas.LogLevelInfo)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Create test user
	userID := uuid.New()
	user := &database.User{
		ID:    userID,
		Sub:   "test-user",
		Email: "test@example.com",
		Name:  "Test User",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create test log entries
	for i := 0; i < 3; i++ {
		logEntry := &database.LogEntry{
			ID:            uuid.New(),
			UserID:        &userID,
			Level:         "INFO",
			Message:       "Test log entry",
			ModelProvider: "openai",
			ModelName:     "gpt-4",
			RequestType:   "chat",
			TotalTokens:   100,
			StatusCode:    200,
			CreatedAt:     time.Now(),
		}
		if err := db.Create(logEntry).Error; err != nil {
			t.Fatalf("Failed to create test log entry: %v", err)
		}
	}

	handler := NewLoggingHandler(logger)

	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue("user_id", userID)
	handler.getBasicMetrics(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Errorf("Expected status %d, got %d", fasthttp.StatusOK, ctx.Response.StatusCode())
	}

	var response struct {
		RecentCalls []database.LogEntry `json:"recent_calls"`
		TotalCalls  int64               `json:"total_calls"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response.TotalCalls != 3 {
		t.Errorf("Expected 3 total calls, got %d", response.TotalCalls)
	}

	if len(response.RecentCalls) != 3 {
		t.Errorf("Expected 3 recent calls, got %d", len(response.RecentCalls))
	}

	// Verify recent calls data
	for _, call := range response.RecentCalls {
		if *call.UserID != userID {
			t.Errorf("Expected user ID %s, got %s", userID, *call.UserID)
		}
		if call.TotalTokens != 100 {
			t.Errorf("Expected 100 tokens, got %d", call.TotalTokens)
		}
	}
}

func TestGetEnhancedLogs_Unauthenticated(t *testing.T) {
	db := testutil.SetupTestDB(t, &database.User{}, &database.LogEntry{})
	logger, err := database.NewPostgresLogger(db, schemas.LogLevelInfo)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	handler := NewLoggingHandler(logger)

	ctx := &fasthttp.RequestCtx{}
	handler.getEnhancedLogs(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	}
}

func TestGetEnhancedLogs_WithLimit(t *testing.T) {
	db := testutil.SetupTestDB(t, &database.User{}, &database.LogEntry{})
	logger, err := database.NewPostgresLogger(db, schemas.LogLevelInfo)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Create test user
	userID := uuid.New()
	user := &database.User{
		ID:    userID,
		Sub:   "test-user",
		Email: "test@example.com",
		Name:  "Test User",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create more log entries than the limit
	for i := 0; i < 10; i++ {
		logEntry := &database.LogEntry{
			ID:              uuid.New(),
			UserID:          &userID,
			Level:           "INFO",
			Message:         "Enhanced log entry",
			ModelProvider:   "openai",
			ModelName:       "gpt-4",
			RequestType:     "chat",
			TotalTokens:     50,
			PromptTokens:    20,
			CompletionTokens: 30,
			CachedTokens:    5,
			StatusCode:      200,
			CreatedAt:       time.Now(),
		}
		if err := db.Create(logEntry).Error; err != nil {
			t.Fatalf("Failed to create test log entry: %v", err)
		}
	}

	handler := NewLoggingHandler(logger)

	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue("user_id", userID)
	ctx.QueryArgs().Set("limit", "5")
	handler.getEnhancedLogs(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Errorf("Expected status %d, got %d", fasthttp.StatusOK, ctx.Response.StatusCode())
	}

	var response struct {
		Logs  []database.LogEntry `json:"logs"`
		Count int                 `json:"count"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response.Count != 5 {
		t.Errorf("Expected 5 logs, got %d", response.Count)
	}

	if len(response.Logs) != 5 {
		t.Errorf("Expected 5 log entries, got %d", len(response.Logs))
	}

	// Verify enhanced log data
	for _, log := range response.Logs {
		if log.TotalTokens != 50 {
			t.Errorf("Expected 50 total tokens, got %d", log.TotalTokens)
		}
		if log.PromptTokens != 20 {
			t.Errorf("Expected 20 prompt tokens, got %d", log.PromptTokens)
		}
		if log.CompletionTokens != 30 {
			t.Errorf("Expected 30 completion tokens, got %d", log.CompletionTokens)
		}
		if log.CachedTokens != 5 {
			t.Errorf("Expected 5 cached tokens, got %d", log.CachedTokens)
		}
	}
}

func TestGetDetailedTokenUsage_Authenticated(t *testing.T) {
	db := testutil.SetupTestDB(t, &database.User{}, &database.LogEntry{})
	logger, err := database.NewPostgresLogger(db, schemas.LogLevelInfo)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Create test user
	userID := uuid.New()
	user := &database.User{
		ID:    userID,
		Sub:   "test-user",
		Email: "test@example.com",
		Name:  "Test User",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create test log entries with different models and providers
	models := []struct {
		provider string
		model    string
		tokens   int
	}{
		{"openai", "gpt-4", 100},
		{"openai", "gpt-3.5-turbo", 50},
		{"anthropic", "claude-3", 75},
	}

	for _, m := range models {
		logEntry := &database.LogEntry{
			ID:               uuid.New(),
			UserID:           &userID,
			Level:            "INFO",
			Message:          "Token usage test",
			ModelProvider:    m.provider,
			ModelName:        m.model,
			RequestType:      "chat",
			TotalTokens:      m.tokens,
			PromptTokens:     m.tokens / 3,
			CompletionTokens: (m.tokens * 2) / 3,
			StatusCode:       200,
			CreatedAt:        time.Now(),
		}
		if err := db.Create(logEntry).Error; err != nil {
			t.Fatalf("Failed to create test log entry: %v", err)
		}
	}

	handler := NewLoggingHandler(logger)

	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue("user_id", userID)
	ctx.QueryArgs().Set("days", "7")
	handler.getDetailedTokenUsage(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Errorf("Expected status %d, got %d", fasthttp.StatusOK, ctx.Response.StatusCode())
	}

	var response struct {
		Usage struct {
			TotalTokens      int                                     `json:"total_tokens"`
			PromptTokens     int                                     `json:"prompt_tokens"`
			CompletionTokens int                                     `json:"completion_tokens"`
			ByModel          map[string]*database.TokenUsageStats   `json:"by_model"`
			ByProvider       map[string]*database.TokenUsageStats `json:"by_provider"`
		} `json:"usage"`
		TimeRange struct {
			Days      int    `json:"days"`
			StartDate string `json:"start_date"`
			EndDate   string `json:"end_date"`
		} `json:"time_range"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	expectedTotal := 100 + 50 + 75
	if response.Usage.TotalTokens != expectedTotal {
		t.Errorf("Expected %d total tokens, got %d", expectedTotal, response.Usage.TotalTokens)
	}

	if len(response.Usage.ByModel) != 3 {
		t.Errorf("Expected 3 models, got %d", len(response.Usage.ByModel))
	}

	if len(response.Usage.ByProvider) != 2 {
		t.Errorf("Expected 2 providers, got %d", len(response.Usage.ByProvider))
	}

	// Verify provider aggregation
	if response.Usage.ByProvider["openai"].TotalTokens != 150 {
		t.Errorf("Expected 150 tokens for OpenAI, got %d", response.Usage.ByProvider["openai"].TotalTokens)
	}

	if response.Usage.ByProvider["anthropic"].TotalTokens != 75 {
		t.Errorf("Expected 75 tokens for Anthropic, got %d", response.Usage.ByProvider["anthropic"].TotalTokens)
	}

	if response.TimeRange.Days != 7 {
		t.Errorf("Expected 7 days, got %d", response.TimeRange.Days)
	}
}

func TestGetTokenUsageSummary_MultipleTimeRanges(t *testing.T) {
	db := testutil.SetupTestDB(t, &database.User{}, &database.LogEntry{})
	logger, err := database.NewPostgresLogger(db, schemas.LogLevelInfo)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Create test user
	userID := uuid.New()
	user := &database.User{
		ID:    userID,
		Sub:   "test-user",
		Email: "test@example.com",
		Name:  "Test User",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create test log entries at different times
	times := []time.Time{
		time.Now(),                        // today
		time.Now().Add(-2 * 24 * time.Hour), // 2 days ago
		time.Now().Add(-10 * 24 * time.Hour), // 10 days ago
		time.Now().Add(-40 * 24 * time.Hour), // 40 days ago
	}

	for i, timestamp := range times {
		logEntry := &database.LogEntry{
			ID:               uuid.New(),
			UserID:           &userID,
			Level:            "INFO",
			Message:          "Summary test",
			ModelProvider:    "openai",
			ModelName:        "gpt-4",
			RequestType:      "chat",
			TotalTokens:      100,
			PromptTokens:     30,
			CompletionTokens: 70,
			StatusCode:       200,
			CreatedAt:        timestamp,
		}
		if err := db.Create(logEntry).Error; err != nil {
			t.Fatalf("Failed to create test log entry %d: %v", i, err)
		}
	}

	handler := NewLoggingHandler(logger)

	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue("user_id", userID)
	handler.getTokenUsageSummary(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Errorf("Expected status %d, got %d", fasthttp.StatusOK, ctx.Response.StatusCode())
	}

	var response struct {
		Summary map[string]interface{} `json:"summary"`
		UpdatedAt string               `json:"updated_at"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Check that all time periods are present
	expectedPeriods := []string{"today", "week", "month", "total"}
	for _, period := range expectedPeriods {
		if _, exists := response.Summary[period]; !exists {
			t.Errorf("Expected period '%s' to be present", period)
		}
	}

	// Verify token counts for different periods
	todayData := response.Summary["today"].(map[string]interface{})
	if todayData["total_tokens"].(float64) != 100 {
		t.Errorf("Expected 100 tokens today, got %v", todayData["total_tokens"])
	}

	weekData := response.Summary["week"].(map[string]interface{})
	if weekData["total_tokens"].(float64) != 200 { // today + 2 days ago
		t.Errorf("Expected 200 tokens this week, got %v", weekData["total_tokens"])
	}

	monthData := response.Summary["month"].(map[string]interface{})
	if monthData["total_tokens"].(float64) != 300 { // today + 2 days + 10 days
		t.Errorf("Expected 300 tokens this month, got %v", monthData["total_tokens"])
	}

	totalData := response.Summary["total"].(map[string]interface{})
	if totalData["total_tokens"].(float64) != 400 { // all entries
		t.Errorf("Expected 400 total tokens, got %v", totalData["total_tokens"])
	}

	if response.UpdatedAt == "" {
		t.Error("Expected updated_at timestamp to be present")
	}
}

func TestGetBasicMetrics_InvalidUserID(t *testing.T) {
	db := testutil.SetupTestDB(t, &database.User{}, &database.LogEntry{})
	logger, err := database.NewPostgresLogger(db, schemas.LogLevelInfo)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	handler := NewLoggingHandler(logger)

	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue("user_id", "invalid-uuid")
	handler.getBasicMetrics(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	}

	var response map[string]string
	if err := json.Unmarshal(ctx.Response.Body(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response["error"] != "Invalid user ID" {
		t.Errorf("Expected 'Invalid user ID' error, got '%s'", response["error"])
	}
}

func TestGetEnhancedLogs_LimitValidation(t *testing.T) {
	db := testutil.SetupTestDB(t, &database.User{}, &database.LogEntry{})
	logger, err := database.NewPostgresLogger(db, schemas.LogLevelInfo)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	userID := uuid.New()
	user := &database.User{
		ID:    userID,
		Sub:   "test-user",
		Email: "test@example.com",
		Name:  "Test User",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	handler := NewLoggingHandler(logger)

	// Test invalid limit (too high)
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue("user_id", userID)
	ctx.QueryArgs().Set("limit", "2000")
	handler.getEnhancedLogs(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Errorf("Expected status %d for high limit, got %d", fasthttp.StatusOK, ctx.Response.StatusCode())
	}

	// Should default to 50 when limit is too high
	var response struct {
		Logs  []database.LogEntry `json:"logs"`
		Count int                 `json:"count"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &response); err == nil {
		// The limit should be capped, so we expect reasonable behavior
		if response.Count > 1000 {
			t.Errorf("Expected reasonable limit, got count %d", response.Count)
		}
	}
}

func TestGetDetailedTokenUsage_DaysValidation(t *testing.T) {
	db := testutil.SetupTestDB(t, &database.User{}, &database.LogEntry{})
	logger, err := database.NewPostgresLogger(db, schemas.LogLevelInfo)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	userID := uuid.New()
	user := &database.User{
		ID:    userID,
		Sub:   "test-user",
		Email: "test@example.com",
		Name:  "Test User",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	handler := NewLoggingHandler(logger)

	// Test invalid days parameter (too high)
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue("user_id", userID)
	ctx.QueryArgs().Set("days", "500")
	handler.getDetailedTokenUsage(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Errorf("Expected status %d, got %d", fasthttp.StatusOK, ctx.Response.StatusCode())
	}

	var response struct {
		TimeRange struct {
			Days int `json:"days"`
		} `json:"time_range"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &response); err == nil {
		// Should be capped at 365
		if response.TimeRange.Days > 365 {
			t.Errorf("Expected days to be capped at 365, got %d", response.TimeRange.Days)
		}
	}
}