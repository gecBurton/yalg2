package database

import (
	"time"
	"sync"
	"strings"

	"context"
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	ID                   uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;"`
	Sub                  string         `json:"sub" gorm:"uniqueIndex;not null"` // OIDC subject identifier
	Email                string         `json:"email" gorm:"index"`
	Name                 string         `json:"name"`
	MaxRequestsPerMinute int            `json:"max_requests_per_minute" gorm:"default:60"` // Rate limit
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
	DeletedAt            gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

// Session represents a user session
type Session struct {
	ID        string         `json:"id" gorm:"primary_key"`
	UserID    uuid.UUID      `json:"user_id" gorm:"type:uuid;not null;index"`
	User      User           `json:"user" gorm:"foreignKey:UserID"`
	IDToken   string         `json:"id_token"`
	ExpiresAt time.Time      `json:"expires_at" gorm:"index"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

// LogEntry represents a log entry stored in PostgreSQL with advanced LLM usage tracking
type LogEntry struct {
	ID             uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID         *uuid.UUID `json:"user_id" gorm:"type:uuid;index:idx_user_created,composite;index:idx_user_provider,composite"` // Foreign key to users table
	User           *User      `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Level          string     `json:"level" gorm:"index:idx_level_created,composite"`      // DEBUG, INFO, WARN, ERROR
	Message        string     `json:"message"`                 // Log message
	RequestID      string     `json:"request_id" gorm:"index"` // Unique request identifier
	ModelProvider  string     `json:"model_provider" gorm:"index:idx_user_provider,composite;index:idx_provider_model,composite"`          // Which AI provider was used
	ModelName      string     `json:"model_name" gorm:"index:idx_provider_model,composite"`              // Model name (e.g., gpt-4, claude-3)
	RequestType    string     `json:"request_type" gorm:"index:idx_type_created,composite"`            // Type: "chat", "completion", "embedding", etc.
	ResponseTimeMs int        `json:"response_time_ms"`        // Response time in milliseconds
	StatusCode     int        `json:"status_code" gorm:"index:idx_status_created,composite"`             // HTTP status code
	ErrorMessage   string     `json:"error_message,omitempty"` // Error message if request failed
	IPAddress      string     `json:"ip_address,omitempty"`    // Client IP (optional)
	UserAgent      string     `json:"user_agent,omitempty"`    // Client user agent (optional)
	
	// Advanced LLM Usage Tracking (from GitHub plugin)
	PromptTokens      int `json:"prompt_tokens" gorm:"index:idx_tokens"`      // Input tokens used
	CompletionTokens  int `json:"completion_tokens" gorm:"index:idx_tokens"`  // Output tokens generated
	TotalTokens       int `json:"total_tokens" gorm:"index:idx_tokens"`       // Total tokens (prompt + completion)
	
	// Detailed Token Information (optional, provider-dependent)
	CachedTokens              int `json:"cached_tokens,omitempty"`                // Cached tokens (efficiency)
	AudioTokens               int `json:"audio_tokens,omitempty"`                 // Audio processing tokens
	ReasoningTokens           int `json:"reasoning_tokens,omitempty"`             // Reasoning tokens (o1 models)
	AcceptedPredictionTokens  int `json:"accepted_prediction_tokens,omitempty"`   // Accepted prediction tokens
	RejectedPredictionTokens  int `json:"rejected_prediction_tokens,omitempty"`   // Rejected prediction tokens
	
	// Request/Response Content
	RequestBody    string `json:"request_body,omitempty" gorm:"type:text"`    // Complete request body
	ResponseBody   string `json:"response_body,omitempty" gorm:"type:text"`   // Complete response body
	
	// Streaming Support
	IsStreaming    bool   `json:"is_streaming" gorm:"index:idx_streaming_created,composite"`                 // Whether this was a streaming request
	StreamStatus   string `json:"stream_status,omitempty"`                   // "start", "update", "complete", "error"
	
	// Error Analysis
	ErrorCategory  string `json:"error_category,omitempty" gorm:"index:idx_error_category,composite"`     // Error categorization
	
	// Multi-modal Support
	InputType      string `json:"input_type,omitempty"`                      // "text", "audio", "image", "multimodal"
	OutputType     string `json:"output_type,omitempty"`                     // "text", "audio", "image"
	
	CreatedAt      time.Time  `json:"created_at" gorm:"index;index:idx_user_created,composite;index:idx_level_created,composite;index:idx_status_created,composite;index:idx_type_created,composite;index:idx_streaming_created,composite;index:idx_error_category,composite;index:idx_tokens,composite"`
}

// Object pool for LogEntry to reduce memory allocation
var entryPool = sync.Pool{
	New: func() interface{} {
		return &LogEntry{}
	},
}

// getLogEntry gets a LogEntry from the pool
func getLogEntry() *LogEntry {
	entry := entryPool.Get().(*LogEntry)
	// Reset the entry to default values
	*entry = LogEntry{}
	return entry
}

// putLogEntry returns a LogEntry to the pool
func putLogEntry(entry *LogEntry) {
	entryPool.Put(entry)
}

// PostgresLogger implements Bifrost's Logger interface and stores logs in PostgreSQL
type PostgresLogger struct {
	db       *gorm.DB
	level    schemas.LogLevel
	logChan  chan *LogEntry
	done     chan struct{}
	wg       sync.WaitGroup
}

// NewPostgresLogger creates a new PostgreSQL logger
func NewPostgresLogger(db *gorm.DB, level schemas.LogLevel) (*PostgresLogger, error) {
	// Auto-migrate the log entry table
	if err := db.AutoMigrate(&LogEntry{}); err != nil {
		return nil, err
	}

	// Let GORM handle index creation through the struct tags
	// Additional custom indexes can be added here if needed
	log.Println("PostgreSQL logger tables and indexes created via GORM auto-migration")

	logger := &PostgresLogger{
		db:      db,
		level:   level,
		logChan: make(chan *LogEntry, 1000), // Buffered channel for async processing
		done:    make(chan struct{}),
	}

	// Start background worker goroutines for async processing
	for i := 0; i < 3; i++ { // 3 worker goroutines
		logger.wg.Add(1)
		go logger.asyncWorker()
	}

	return logger, nil
}

// Debug logs a debug message
func (l *PostgresLogger) Debug(msg string) {
	if l.level <= schemas.LogLevelDebug {
		l.logEntry(schemas.LogLevelDebug, msg, nil)
	}
}

// Info logs an info message
func (l *PostgresLogger) Info(msg string) {
	if l.level <= schemas.LogLevelInfo {
		l.logEntry(schemas.LogLevelInfo, msg, nil)
	}
}

// Warn logs a warning message
func (l *PostgresLogger) Warn(msg string) {
	if l.level <= schemas.LogLevelWarn {
		l.logEntry(schemas.LogLevelWarn, msg, nil)
	}
}

// Error logs an error message (implements schemas.Logger interface)
func (l *PostgresLogger) Error(err error) {
	if l.level <= schemas.LogLevelError {
		l.logEntry(schemas.LogLevelError, err.Error(), nil)
	}
}

// ErrorMsg logs an error message from string
func (l *PostgresLogger) ErrorMsg(msg string) {
	if l.level <= schemas.LogLevelError {
		l.logEntry(schemas.LogLevelError, msg, nil)
	}
}

// DebugWithContext logs a debug message with context
func (l *PostgresLogger) DebugWithContext(ctx context.Context, msg string) {
	if l.level <= schemas.LogLevelDebug {
		l.logEntry(schemas.LogLevelDebug, msg, &ctx)
	}
}

// InfoWithContext logs an info message with context
func (l *PostgresLogger) InfoWithContext(ctx context.Context, msg string) {
	if l.level <= schemas.LogLevelInfo {
		l.logEntry(schemas.LogLevelInfo, msg, &ctx)
	}
}

// WarnWithContext logs a warning message with context
func (l *PostgresLogger) WarnWithContext(ctx context.Context, msg string) {
	if l.level <= schemas.LogLevelWarn {
		l.logEntry(schemas.LogLevelWarn, msg, &ctx)
	}
}

// ErrorWithContext logs an error message with context
func (l *PostgresLogger) ErrorWithContext(ctx context.Context, msg string) {
	if l.level <= schemas.LogLevelError {
		l.logEntry(schemas.LogLevelError, msg, &ctx)
	}
}

// asyncWorker processes log entries asynchronously
func (l *PostgresLogger) asyncWorker() {
	defer l.wg.Done()
	for {
		select {
		case entry := <-l.logChan:
			if entry != nil {
				l.processLogEntry(entry)
				putLogEntry(entry) // Return to pool
			}
		case <-l.done:
			return
		}
	}
}

// processLogEntry writes a log entry to the database
func (l *PostgresLogger) processLogEntry(entry *LogEntry) {
	if err := l.db.Create(entry).Error; err != nil {
		// Fallback to standard logging if database write fails
		log.Printf("[%s] %s (DB write failed: %v)", entry.Level, entry.Message, err)
	}
}

// logEntry creates and queues a log entry for async processing
func (l *PostgresLogger) logEntry(level schemas.LogLevel, message string, ctx *context.Context) {
	entry := getLogEntry() // Get from pool
	entry.Level = levelToString(level)
	entry.Message = message
	entry.CreatedAt = time.Now()

	// Extract context information if available
	if ctx != nil {
		l.enrichFromContext(entry, *ctx)
	}

	// Queue for async processing
	select {
	case l.logChan <- entry:
		// Successfully queued
	default:
		// Channel is full, fall back to sync logging
		l.processLogEntry(entry)
		putLogEntry(entry)
	}
}

// enrichFromContext extracts useful information from the context
func (l *PostgresLogger) enrichFromContext(entry *LogEntry, ctx context.Context) {
	// Extract user ID if available
	if userIDValue := ctx.Value("user_id"); userIDValue != nil {
		if uid, ok := userIDValue.(uuid.UUID); ok {
			entry.UserID = &uid
		}
	}

	// Extract request ID if available
	if requestIDValue := ctx.Value("request_id"); requestIDValue != nil {
		if rid, ok := requestIDValue.(string); ok {
			entry.RequestID = rid
		}
	}

	// Extract timing information if available
	if startTimeValue := ctx.Value("request_start_time"); startTimeValue != nil {
		if startTime, ok := startTimeValue.(time.Time); ok {
			entry.ResponseTimeMs = int(time.Since(startTime).Milliseconds())
		}
	}

	// Extract request body if available (limit size to prevent DB bloat)
	if reqBodyValue := ctx.Value("request_body"); reqBodyValue != nil {
		if reqBody, ok := reqBodyValue.([]byte); ok {
			if len(reqBody) < 10000 { // Limit to 10KB
				entry.RequestBody = string(reqBody)
			} else {
				entry.RequestBody = string(reqBody[:10000]) + "... [truncated]"
			}
		}
	}

	// Extract response body if available (limit size)
	if respBodyValue := ctx.Value("response_body"); respBodyValue != nil {
		if respBody, ok := respBodyValue.([]byte); ok {
			if len(respBody) < 10000 { // Limit to 10KB
				entry.ResponseBody = string(respBody)
			} else {
				entry.ResponseBody = string(respBody[:10000]) + "... [truncated]"
			}
		}
	}

	// Extract streaming status
	if streamingValue := ctx.Value("is_streaming"); streamingValue != nil {
		if isStreaming, ok := streamingValue.(bool); ok {
			entry.IsStreaming = isStreaming
		}
	}

	// Extract stream status
	if streamStatusValue := ctx.Value("stream_status"); streamStatusValue != nil {
		if streamStatus, ok := streamStatusValue.(string); ok {
			entry.StreamStatus = streamStatus
		}
	}

	// Extract IP address
	if ipValue := ctx.Value("client_ip"); ipValue != nil {
		if ip, ok := ipValue.(string); ok {
			entry.IPAddress = ip
		}
	}

	// Extract user agent
	if uaValue := ctx.Value("user_agent"); uaValue != nil {
		if ua, ok := uaValue.(string); ok {
			entry.UserAgent = ua
		}
	}

	// Extract request information if available
	if reqValue := ctx.Value("bifrost_request"); reqValue != nil {
		if req, ok := reqValue.(*schemas.BifrostRequest); ok {
			entry.ModelProvider = string(req.Provider)
			entry.ModelName = req.Model
			// Better request type classification based on input type
			if req.Input.ChatCompletionInput != nil {
				entry.RequestType = "chat"
			} else if req.Input.TextCompletionInput != nil {
				entry.RequestType = "completion"
			} else if req.Input.EmbeddingInput != nil {
				entry.RequestType = "embedding"
			} else {
				entry.RequestType = "unknown"
			}
		}
	}

	// Extract response information if available
	if respValue := ctx.Value("bifrost_response"); respValue != nil {
		if resp, ok := respValue.(*schemas.BifrostResponse); ok {
			entry.StatusCode = 200
			if resp.Usage != nil {
				entry.TotalTokens = resp.Usage.TotalTokens
				entry.PromptTokens = resp.Usage.PromptTokens
				entry.CompletionTokens = resp.Usage.CompletionTokens
				
				// Handle detailed token information if available
				if resp.Usage.TokenDetails != nil {
					entry.CachedTokens = resp.Usage.TokenDetails.CachedTokens
					entry.AudioTokens = resp.Usage.TokenDetails.AudioTokens
				}
				
				if resp.Usage.CompletionTokensDetails != nil {
					entry.ReasoningTokens = resp.Usage.CompletionTokensDetails.ReasoningTokens
					entry.AcceptedPredictionTokens = resp.Usage.CompletionTokensDetails.AcceptedPredictionTokens
					entry.RejectedPredictionTokens = resp.Usage.CompletionTokensDetails.RejectedPredictionTokens
				}
			}
		}
	}

	// Extract error information if available
	if errValue := ctx.Value("bifrost_error"); errValue != nil {
		if bifrostErr, ok := errValue.(*schemas.BifrostError); ok {
			if bifrostErr.StatusCode != nil {
				entry.StatusCode = *bifrostErr.StatusCode
			} else {
				entry.StatusCode = 500
			}
			entry.ErrorMessage = bifrostErr.Error.Message
			entry.ErrorCategory = l.categorizeError(bifrostErr)
		}
	}
}

// levelToString converts LogLevel to string
func levelToString(level schemas.LogLevel) string {
	switch level {
	case schemas.LogLevelDebug:
		return "DEBUG"
	case schemas.LogLevelInfo:
		return "INFO"
	case schemas.LogLevelWarn:
		return "WARN"
	case schemas.LogLevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// GetRecentCallsForUser returns recent API calls for a specific user
func (l *PostgresLogger) GetRecentCallsForUser(userID uuid.UUID, limit int) ([]LogEntry, error) {
	var entries []LogEntry
	err := l.db.Where("user_id = ? AND model_provider != ''", userID).
		Order("created_at DESC").
		Limit(limit).
		Find(&entries).Error
	return entries, err
}

// GetTotalCallsForUser returns the total number of API calls for a specific user
func (l *PostgresLogger) GetTotalCallsForUser(userID uuid.UUID) (int64, error) {
	var count int64
	err := l.db.Model(&LogEntry{}).Where("user_id = ? AND model_provider != ''", userID).Count(&count).Error
	return count, err
}

// categorizeError categorizes errors for better analysis
func (l *PostgresLogger) categorizeError(bifrostErr *schemas.BifrostError) string {
	if bifrostErr.StatusCode == nil {
		return "unknown"
	}

	switch *bifrostErr.StatusCode {
	case 400:
		return "client_error"
	case 401:
		return "auth_error"
	case 403:
		return "permission_error"
	case 404:
		return "not_found"
	case 429:
		return "rate_limit"
	case 500, 502, 503, 504:
		return "server_error"
	default:
		if *bifrostErr.StatusCode >= 400 && *bifrostErr.StatusCode < 500 {
			return "client_error"
		}
		if *bifrostErr.StatusCode >= 500 {
			return "server_error"
		}
		return "unknown"
	}
}

// LogAPIRequestWithContext logs an API request with enhanced context and detailed token tracking
func (l *PostgresLogger) LogAPIRequestWithContext(userID uuid.UUID, requestType, model, provider string, statusCode int, errorMessage string, responseTimeMs int, tokensUsed int, requestID, clientIP, userAgent string, isStreaming bool, requestBody, responseBody []byte) {
	entry := getLogEntry() // Use pool
	entry.UserID = &userID
	entry.Level = "INFO"
	entry.Message = fmt.Sprintf("API request: %s", requestType)
	entry.RequestID = requestID
	entry.ModelProvider = provider
	entry.ModelName = model
	entry.RequestType = requestType
	entry.ResponseTimeMs = responseTimeMs
	entry.StatusCode = statusCode
	entry.ErrorMessage = errorMessage
	entry.IPAddress = clientIP
	entry.UserAgent = userAgent
	entry.IsStreaming = isStreaming
	entry.CreatedAt = time.Now()
	
	// Enhanced token tracking
	entry.TotalTokens = tokensUsed
	// TODO: Extract detailed token breakdown from response
	// For now, we estimate: ~75% completion, ~25% prompt for chat/completion requests
	if tokensUsed > 0 && (requestType == "chat" || requestType == "completion") {
		entry.CompletionTokens = int(float64(tokensUsed) * 0.75)
		entry.PromptTokens = tokensUsed - entry.CompletionTokens
	}
	
	// Determine input/output types based on request
	entry.InputType = l.determineInputType(requestType, requestBody)
	entry.OutputType = l.determineOutputType(requestType, responseBody)

	// Add request/response bodies if not too large
	if len(requestBody) < 10000 {
		entry.RequestBody = string(requestBody)
	} else if len(requestBody) > 0 {
		entry.RequestBody = string(requestBody[:10000]) + "... [truncated]"
	}
	
	if len(responseBody) < 10000 {
		entry.ResponseBody = string(responseBody)
	} else if len(responseBody) > 0 {
		entry.ResponseBody = string(responseBody[:10000]) + "... [truncated]"
	}

	// Set stream status based on conditions
	if isStreaming {
		if statusCode >= 200 && statusCode < 300 {
			entry.StreamStatus = "complete"
		} else {
			entry.StreamStatus = "error"
		}
	}

	// Categorize errors
	if errorMessage != "" {
		entry.ErrorCategory = l.categorizeErrorByStatus(statusCode)
	}

	// Queue for async processing
	select {
	case l.logChan <- entry:
		// Successfully queued
	default:
		// Channel is full, fall back to sync logging
		l.processLogEntry(entry)
		putLogEntry(entry)
	}
}

// LogAPIRequest logs an API request directly (for all requests, successful or not)
func (l *PostgresLogger) LogAPIRequest(userID uuid.UUID, requestType, model, provider string, statusCode int, errorMessage string, responseTimeMs int, tokensUsed int) {
	l.LogAPIRequestWithContext(userID, requestType, model, provider, statusCode, errorMessage, responseTimeMs, tokensUsed, fmt.Sprintf("api-%d", time.Now().UnixNano()), "", "", false, nil, nil)
}

// categorizeErrorByStatus categorizes errors by HTTP status code
func (l *PostgresLogger) categorizeErrorByStatus(statusCode int) string {
	switch statusCode {
	case 400:
		return "client_error"
	case 401:
		return "auth_error"
	case 403:
		return "permission_error"
	case 404:
		return "not_found"
	case 429:
		return "rate_limit"
	case 500, 502, 503, 504:
		return "server_error"
	default:
		if statusCode >= 400 && statusCode < 500 {
			return "client_error"
		}
		if statusCode >= 500 {
			return "server_error"
		}
		return "success"
	}
}

// LogStreamingUpdate logs a streaming response update
func (l *PostgresLogger) LogStreamingUpdate(userID uuid.UUID, requestID string, status string, partialContent string) {
	entry := getLogEntry()
	entry.UserID = &userID
	entry.Level = "INFO"
	entry.Message = fmt.Sprintf("Streaming update: %s", status)
	entry.RequestID = requestID
	entry.IsStreaming = true
	entry.StreamStatus = status
	entry.ResponseBody = partialContent
	entry.CreatedAt = time.Now()

	// Queue for async processing
	select {
	case l.logChan <- entry:
	default:
		l.processLogEntry(entry)
		putLogEntry(entry)
	}
}

// CleanupOldLogs removes log entries older than the specified duration
func (l *PostgresLogger) CleanupOldLogs(olderThan time.Duration) error {
	cutoff := time.Now().Add(-olderThan)
	result := l.db.Where("created_at < ?", cutoff).Delete(&LogEntry{})
	if result.Error != nil {
		return result.Error
	}
	log.Printf("[PostgresLogger] Cleaned up %d old log entries", result.RowsAffected)
	return nil
}

// StartPeriodicCleanup starts a background goroutine that periodically cleans old logs
func (l *PostgresLogger) StartPeriodicCleanup(cleanupInterval time.Duration, retentionPeriod time.Duration) {
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := l.CleanupOldLogs(retentionPeriod); err != nil {
					log.Printf("[PostgresLogger] Cleanup failed: %v", err)
				}
			case <-l.done:
				return
			}
		}
	}()
}

// determineInputType analyzes the request to determine input type
func (l *PostgresLogger) determineInputType(requestType string, requestBody []byte) string {
	switch requestType {
	case "chat":
		return "text"
	case "completion":
		return "text"
	case "embedding":
		return "text"
	case "speech":
		return "audio"
	case "transcription":
		return "audio"
	default:
		// Try to detect from request body
		if len(requestBody) > 0 {
			// Simple heuristic: if body contains "audio" or "image" keywords
			bodyStr := string(requestBody)
			if strings.Contains(bodyStr, "audio") || strings.Contains(bodyStr, "speech") {
				return "audio"
			}
			if strings.Contains(bodyStr, "image") || strings.Contains(bodyStr, "vision") {
				return "image"
			}
		}
		return "text"
	}
}

// determineOutputType analyzes the response to determine output type
func (l *PostgresLogger) determineOutputType(requestType string, responseBody []byte) string {
	switch requestType {
	case "speech":
		return "audio"
	case "transcription":
		return "text"
	default:
		return "text"
	}
}

// Close shuts down the async workers gracefully
func (l *PostgresLogger) Close() {
	close(l.done)
	close(l.logChan)
	l.wg.Wait()
}

// GetDB returns the database connection for direct access
func (l *PostgresLogger) GetDB() *gorm.DB {
	return l.db
}

// GetRecentCallsWithFilters returns recent API calls for a user with filtering options
func (l *PostgresLogger) GetRecentCallsWithFilters(userID uuid.UUID, limit int, provider, requestType string, onlyErrors bool) ([]LogEntry, error) {
	query := l.db.Where("user_id = ?", userID)
	
	if provider != "" {
		query = query.Where("model_provider = ?", provider)
	}
	
	if requestType != "" {
		query = query.Where("request_type = ?", requestType)
	}
	
	if onlyErrors {
		query = query.Where("error_message IS NOT NULL AND error_message != ''")
	} else {
		// Use the performance index for successful requests
		query = query.Where("error_message IS NULL OR error_message = ''")
	}

	var entries []LogEntry
	err := query.Order("created_at DESC").Limit(limit).Find(&entries).Error
	return entries, err
}

// GetErrorStatsByCategory returns error statistics grouped by category
func (l *PostgresLogger) GetErrorStatsByCategory(userID *uuid.UUID, timeRange time.Duration) (map[string]int64, error) {
	cutoff := time.Now().Add(-timeRange)
	query := l.db.Model(&LogEntry{}).Where("created_at >= ? AND error_category IS NOT NULL AND error_category != ''", cutoff)
	
	if userID != nil {
		query = query.Where("user_id = ?", *userID)
	}
	
	type result struct {
		ErrorCategory string `json:"error_category"`
		Count         int64  `json:"count"`
	}
	
	var results []result
	err := query.Select("error_category, COUNT(*) as count").Group("error_category").Find(&results).Error
	if err != nil {
		return nil, err
	}
	
	stats := make(map[string]int64)
	for _, r := range results {
		stats[r.ErrorCategory] = r.Count
	}
	
	return stats, nil
}

// GetStreamingStats returns statistics about streaming requests
func (l *PostgresLogger) GetStreamingStats(userID uuid.UUID, timeRange time.Duration) (map[string]interface{}, error) {
	cutoff := time.Now().Add(-timeRange)
	
	type streamingResult struct {
		StreamStatus string `json:"stream_status"`
		Count        int64  `json:"count"`
		AvgResponse  int64  `json:"avg_response_time"`
	}
	
	var results []streamingResult
	err := l.db.Model(&LogEntry{}).Where(
		"user_id = ? AND created_at >= ? AND is_streaming = true", userID, cutoff,
	).Select(
		"stream_status, COUNT(*) as count, AVG(response_time_ms) as avg_response",
	).Group("stream_status").Find(&results).Error
	
	if err != nil {
		return nil, err
	}
	
	stats := make(map[string]interface{})
	for _, r := range results {
		stats[r.StreamStatus] = map[string]interface{}{
			"count":              r.Count,
			"avg_response_time":  r.AvgResponse,
		}
	}
	
	return stats, nil
}

// GetTokenUsageByModel returns token usage statistics by model
func (l *PostgresLogger) GetTokenUsageByModel(userID uuid.UUID, timeRange time.Duration) (map[string]int64, error) {
	cutoff := time.Now().Add(-timeRange)
	
	type tokenResult struct {
		ModelName  string `json:"model_name"`
		TotalTokens int64  `json:"total_tokens"`
	}
	
	var results []tokenResult
	err := l.db.Model(&LogEntry{}).Where(
		"user_id = ? AND created_at >= ? AND total_tokens > 0", userID, cutoff,
	).Select(
		"model_name, SUM(total_tokens) as total_tokens",
	).Group("model_name").Find(&results).Error
	
	if err != nil {
		return nil, err
	}
	
	usage := make(map[string]int64)
	for _, r := range results {
		usage[r.ModelName] = r.TotalTokens
	}
	
	return usage, nil
}

// AdvancedTokenUsage provides comprehensive token usage statistics
type AdvancedTokenUsage struct {
	TotalTokens      int                             `json:"total_tokens"`
	PromptTokens     int                             `json:"prompt_tokens"`
	CompletionTokens int                             `json:"completion_tokens"`
	CachedTokens     int                             `json:"cached_tokens,omitempty"`
	AudioTokens      int                             `json:"audio_tokens,omitempty"`
	ReasoningTokens  int                             `json:"reasoning_tokens,omitempty"`
	ByModel          map[string]*ModelTokenUsage     `json:"by_model"`
	ByProvider       map[string]*ProviderTokenUsage  `json:"by_provider"`
}

// ModelTokenUsage tracks detailed token usage for a specific model
type ModelTokenUsage struct {
	TotalTokens      int `json:"total_tokens"`
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	CachedTokens     int `json:"cached_tokens,omitempty"`
	AudioTokens      int `json:"audio_tokens,omitempty"`
	ReasoningTokens  int `json:"reasoning_tokens,omitempty"`
	RequestCount     int `json:"request_count"`
}

// ProviderTokenUsage tracks detailed token usage for a specific provider
type ProviderTokenUsage struct {
	TotalTokens      int `json:"total_tokens"`
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	CachedTokens     int `json:"cached_tokens,omitempty"`
	AudioTokens      int `json:"audio_tokens,omitempty"`
	ReasoningTokens  int `json:"reasoning_tokens,omitempty"`
	RequestCount     int `json:"request_count"`
}

// GetAdvancedTokenUsageForUser returns comprehensive token usage statistics
func (l *PostgresLogger) GetAdvancedTokenUsageForUser(userID uuid.UUID, timeRange time.Duration) (*AdvancedTokenUsage, error) {
	cutoff := time.Now().Add(-timeRange)
	
	var logs []LogEntry
	err := l.db.Where("user_id = ? AND created_at >= ? AND total_tokens > 0", userID, cutoff).Find(&logs).Error
	if err != nil {
		return nil, err
	}

	usage := &AdvancedTokenUsage{
		ByModel:    make(map[string]*ModelTokenUsage),
		ByProvider: make(map[string]*ProviderTokenUsage),
	}

	for _, log := range logs {
		// Accumulate totals
		usage.TotalTokens += log.TotalTokens
		usage.PromptTokens += log.PromptTokens
		usage.CompletionTokens += log.CompletionTokens
		usage.CachedTokens += log.CachedTokens
		usage.AudioTokens += log.AudioTokens
		usage.ReasoningTokens += log.ReasoningTokens

		// Accumulate by model
		if usage.ByModel[log.ModelName] == nil {
			usage.ByModel[log.ModelName] = &ModelTokenUsage{}
		}
		modelUsage := usage.ByModel[log.ModelName]
		modelUsage.TotalTokens += log.TotalTokens
		modelUsage.PromptTokens += log.PromptTokens
		modelUsage.CompletionTokens += log.CompletionTokens
		modelUsage.CachedTokens += log.CachedTokens
		modelUsage.AudioTokens += log.AudioTokens
		modelUsage.ReasoningTokens += log.ReasoningTokens
		modelUsage.RequestCount++

		// Accumulate by provider
		if usage.ByProvider[log.ModelProvider] == nil {
			usage.ByProvider[log.ModelProvider] = &ProviderTokenUsage{}
		}
		providerUsage := usage.ByProvider[log.ModelProvider]
		providerUsage.TotalTokens += log.TotalTokens
		providerUsage.PromptTokens += log.PromptTokens
		providerUsage.CompletionTokens += log.CompletionTokens
		providerUsage.CachedTokens += log.CachedTokens
		providerUsage.AudioTokens += log.AudioTokens
		providerUsage.ReasoningTokens += log.ReasoningTokens
		providerUsage.RequestCount++
	}

	return usage, nil
}

// GetEnhancedLogsForUser returns recent logs with detailed token information
func (l *PostgresLogger) GetEnhancedLogsForUser(userID uuid.UUID, limit int) ([]LogEntry, error) {
	var entries []LogEntry
	err := l.db.Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).
		Find(&entries).Error
	return entries, err
}
