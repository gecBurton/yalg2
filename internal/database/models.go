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

// Constants for configuration
const (
	// MAX_BODY_SIZE removed (request/response body logging disabled)
	WORKER_COUNT          = 3
	LOG_CHANNEL_BUFFER    = 1000
	TOKEN_ESTIMATION_RATIO = 0.75
)

// Request type to input/output type mappings
var (
	requestTypeToInputType = map[string]string{
		"chat":         "text",
		"completion":   "text",
		"embedding":    "text",
		"speech":       "audio",
		"transcription": "audio",
	}
	
	requestTypeToOutputType = map[string]string{
		"speech":       "audio",
		"transcription": "text",
	}
)

// User represents a user in the system
type User struct {
	ID                   uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;"`
	Sub                  string         `json:"sub" gorm:"uniqueIndex;not null"` // OIDC subject identifier
	Email                string         `json:"email" gorm:"index"`
	Name                 string         `json:"name"`
	IsAdmin              bool           `json:"is_admin" gorm:"default:false"` // Admin privileges
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
	
	// Request/Response Content - REMOVED for security (sensitive data)
	
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

// truncateBody function removed (request/response body logging disabled for security)

// categorizeHTTPStatus categorizes HTTP status codes into error categories
func categorizeHTTPStatus(statusCode int) string {
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
		logChan: make(chan *LogEntry, LOG_CHANNEL_BUFFER), // Buffered channel for async processing
		done:    make(chan struct{}),
	}

	// Start background worker goroutines for async processing
	for i := 0; i < WORKER_COUNT; i++ {
		logger.wg.Add(1)
		go logger.asyncWorker()
	}

	return logger, nil
}

// log is the base logging method that handles level checking and routing
func (l *PostgresLogger) log(level schemas.LogLevel, msg string, ctx *context.Context) {
	if l.level <= level {
		l.logEntry(level, msg, ctx)
	}
}

// Debug logs a debug message
func (l *PostgresLogger) Debug(msg string) {
	l.log(schemas.LogLevelDebug, msg, nil)
}

// Info logs an info message
func (l *PostgresLogger) Info(msg string) {
	l.log(schemas.LogLevelInfo, msg, nil)
}

// Warn logs a warning message
func (l *PostgresLogger) Warn(msg string) {
	l.log(schemas.LogLevelWarn, msg, nil)
}

// Error logs an error message (implements schemas.Logger interface)
func (l *PostgresLogger) Error(err error) {
	l.log(schemas.LogLevelError, err.Error(), nil)
}

// ErrorMsg logs an error message from string
func (l *PostgresLogger) ErrorMsg(msg string) {
	l.log(schemas.LogLevelError, msg, nil)
}

// DebugWithContext logs a debug message with context
func (l *PostgresLogger) DebugWithContext(ctx context.Context, msg string) {
	l.log(schemas.LogLevelDebug, msg, &ctx)
}

// InfoWithContext logs an info message with context
func (l *PostgresLogger) InfoWithContext(ctx context.Context, msg string) {
	l.log(schemas.LogLevelInfo, msg, &ctx)
}

// WarnWithContext logs a warning message with context
func (l *PostgresLogger) WarnWithContext(ctx context.Context, msg string) {
	l.log(schemas.LogLevelWarn, msg, &ctx)
}

// ErrorWithContext logs an error message with context
func (l *PostgresLogger) ErrorWithContext(ctx context.Context, msg string) {
	l.log(schemas.LogLevelError, msg, &ctx)
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
	l.extractUserAndRequest(entry, ctx)
	l.extractTiming(entry, ctx)
	l.extractBodies(entry, ctx)
	l.extractStreaming(entry, ctx)
	l.extractClientInfo(entry, ctx)
	l.extractBifrostData(entry, ctx)
	l.extractErrorInfo(entry, ctx)
}

// extractUserAndRequest extracts user ID and request ID from context
func (l *PostgresLogger) extractUserAndRequest(entry *LogEntry, ctx context.Context) {
	if userIDValue := ctx.Value("user_id"); userIDValue != nil {
		if uid, ok := userIDValue.(uuid.UUID); ok {
			entry.UserID = &uid
		}
	}

	if requestIDValue := ctx.Value("request_id"); requestIDValue != nil {
		if rid, ok := requestIDValue.(string); ok {
			entry.RequestID = rid
		}
	}
}

// extractTiming extracts timing information from context
func (l *PostgresLogger) extractTiming(entry *LogEntry, ctx context.Context) {
	if startTimeValue := ctx.Value("request_start_time"); startTimeValue != nil {
		if startTime, ok := startTimeValue.(time.Time); ok {
			entry.ResponseTimeMs = int(time.Since(startTime).Milliseconds())
		}
	}
}

// extractBodies extracts request and response bodies from context
func (l *PostgresLogger) extractBodies(entry *LogEntry, ctx context.Context) {
	// Request/Response body logging removed for security
}

// extractStreaming extracts streaming-related information from context
func (l *PostgresLogger) extractStreaming(entry *LogEntry, ctx context.Context) {
	if streamingValue := ctx.Value("is_streaming"); streamingValue != nil {
		if isStreaming, ok := streamingValue.(bool); ok {
			entry.IsStreaming = isStreaming
		}
	}

	if streamStatusValue := ctx.Value("stream_status"); streamStatusValue != nil {
		if streamStatus, ok := streamStatusValue.(string); ok {
			entry.StreamStatus = streamStatus
		}
	}
}

// extractClientInfo extracts client IP and user agent from context
func (l *PostgresLogger) extractClientInfo(entry *LogEntry, ctx context.Context) {
	if ipValue := ctx.Value("client_ip"); ipValue != nil {
		if ip, ok := ipValue.(string); ok {
			entry.IPAddress = ip
		}
	}

	if uaValue := ctx.Value("user_agent"); uaValue != nil {
		if ua, ok := uaValue.(string); ok {
			entry.UserAgent = ua
		}
	}
}

// extractBifrostData extracts Bifrost request and response information from context
func (l *PostgresLogger) extractBifrostData(entry *LogEntry, ctx context.Context) {
	l.extractBifrostRequest(entry, ctx)
	l.extractBifrostResponse(entry, ctx)
}

// extractBifrostRequest extracts Bifrost request information from context
func (l *PostgresLogger) extractBifrostRequest(entry *LogEntry, ctx context.Context) {
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
}

// extractBifrostResponse extracts Bifrost response information from context
func (l *PostgresLogger) extractBifrostResponse(entry *LogEntry, ctx context.Context) {
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
}

// extractErrorInfo extracts error information from context
func (l *PostgresLogger) extractErrorInfo(entry *LogEntry, ctx context.Context) {
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
	return categorizeHTTPStatus(*bifrostErr.StatusCode)
}

// LogAPIRequestWithContext logs an API request with enhanced context and detailed token tracking
func (l *PostgresLogger) LogAPIRequestWithContext(userID uuid.UUID, requestType, model, provider string, statusCode int, errorMessage string, responseTimeMs int, tokensUsed int, requestID, clientIP, userAgent string, isStreaming bool, requestBody, responseBody []byte) {
	entry := getLogEntry() // Use pool
	
	l.populateBasicFields(entry, userID, requestType, model, provider, statusCode, errorMessage, responseTimeMs, requestID, clientIP, userAgent, isStreaming)
	l.populateTokenTracking(entry, tokensUsed, requestType)
	l.populateRequestResponseData(entry, requestType, requestBody, responseBody)
	l.populateStreamingStatus(entry, isStreaming, statusCode)
	l.populateErrorCategory(entry, errorMessage, statusCode)
	
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

// populateBasicFields sets the basic log entry fields
func (l *PostgresLogger) populateBasicFields(entry *LogEntry, userID uuid.UUID, requestType, model, provider string, statusCode int, errorMessage string, responseTimeMs int, requestID, clientIP, userAgent string, isStreaming bool) {
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
}

// populateTokenTracking sets token usage fields with estimation
func (l *PostgresLogger) populateTokenTracking(entry *LogEntry, tokensUsed int, requestType string) {
	entry.TotalTokens = tokensUsed
	// TODO: Extract detailed token breakdown from response
	// For now, we estimate based on typical chat/completion ratios
	if tokensUsed > 0 && (requestType == "chat" || requestType == "completion") {
		entry.CompletionTokens = int(float64(tokensUsed) * TOKEN_ESTIMATION_RATIO)
		entry.PromptTokens = tokensUsed - entry.CompletionTokens
	}
}

// populateRequestResponseData sets request/response data fields
func (l *PostgresLogger) populateRequestResponseData(entry *LogEntry, requestType string, requestBody, responseBody []byte) {
	// Determine input/output types based on request
	entry.InputType = l.determineInputType(requestType, requestBody)
	entry.OutputType = l.determineOutputType(requestType, responseBody)

	// Request/Response body logging removed for security
}

// populateStreamingStatus sets streaming-related status fields
func (l *PostgresLogger) populateStreamingStatus(entry *LogEntry, isStreaming bool, statusCode int) {
	if isStreaming {
		if statusCode >= 200 && statusCode < 300 {
			entry.StreamStatus = "complete"
		} else {
			entry.StreamStatus = "error"
		}
	}
}

// populateErrorCategory sets error categorization fields
func (l *PostgresLogger) populateErrorCategory(entry *LogEntry, errorMessage string, statusCode int) {
	if errorMessage != "" {
		entry.ErrorCategory = categorizeHTTPStatus(statusCode)
	}
}

// LogAPIRequest logs an API request directly (for all requests, successful or not)
func (l *PostgresLogger) LogAPIRequest(userID uuid.UUID, requestType, model, provider string, statusCode int, errorMessage string, responseTimeMs int, tokensUsed int) {
	l.LogAPIRequestWithContext(userID, requestType, model, provider, statusCode, errorMessage, responseTimeMs, tokensUsed, fmt.Sprintf("api-%d", time.Now().UnixNano()), "", "", false, nil, nil)
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
	// Response body logging removed for security
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
	if inputType, exists := requestTypeToInputType[requestType]; exists {
		return inputType
	}
	return l.detectInputTypeFromBody(requestBody)
}

// detectInputTypeFromBody detects input type from request body content
func (l *PostgresLogger) detectInputTypeFromBody(requestBody []byte) string {
	if len(requestBody) == 0 {
		return "text"
	}
	
	// Simple heuristic: if body contains keywords
	bodyStr := string(requestBody)
	if strings.Contains(bodyStr, "audio") || strings.Contains(bodyStr, "speech") {
		return "audio"
	}
	if strings.Contains(bodyStr, "image") || strings.Contains(bodyStr, "vision") {
		return "image"
	}
	return "text"
}

// determineOutputType analyzes the response to determine output type
func (l *PostgresLogger) determineOutputType(requestType string, _ []byte) string {
	if outputType, exists := requestTypeToOutputType[requestType]; exists {
		return outputType
	}
	return "text" // default
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

// TokenUsageStats represents detailed token usage statistics
type TokenUsageStats struct {
	TotalTokens      int `json:"total_tokens"`
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	CachedTokens     int `json:"cached_tokens,omitempty"`
	AudioTokens      int `json:"audio_tokens,omitempty"`
	ReasoningTokens  int `json:"reasoning_tokens,omitempty"`
	RequestCount     int `json:"request_count"`
}

// AdvancedTokenUsage provides comprehensive token usage statistics
type AdvancedTokenUsage struct {
	TokenUsageStats
	ByModel    map[string]*TokenUsageStats `json:"by_model"`
	ByProvider map[string]*TokenUsageStats `json:"by_provider"`
}

// GetAdvancedTokenUsageForUser returns comprehensive token usage statistics
func (l *PostgresLogger) GetAdvancedTokenUsageForUser(userID uuid.UUID, timeRange time.Duration) (*AdvancedTokenUsage, error) {
	logs, err := l.getTokenUsageLogs(userID, timeRange)
	if err != nil {
		return nil, err
	}
	return l.aggregateTokenUsage(logs), nil
}

// getTokenUsageLogs fetches log entries with token usage for a user within a time range
func (l *PostgresLogger) getTokenUsageLogs(userID uuid.UUID, timeRange time.Duration) ([]LogEntry, error) {
	cutoff := time.Now().Add(-timeRange)
	var logs []LogEntry
	err := l.db.Where("user_id = ? AND created_at >= ? AND total_tokens > 0", userID, cutoff).Find(&logs).Error
	return logs, err
}

// aggregateTokenUsage processes log entries and aggregates token usage statistics
func (l *PostgresLogger) aggregateTokenUsage(logs []LogEntry) *AdvancedTokenUsage {
	usage := &AdvancedTokenUsage{
		ByModel:    make(map[string]*TokenUsageStats),
		ByProvider: make(map[string]*TokenUsageStats),
	}

	for _, log := range logs {
		l.accumulateOverallTokens(usage, log)
		l.accumulateModelTokens(usage, log)
		l.accumulateProviderTokens(usage, log)
	}

	return usage
}

// accumulateOverallTokens adds token counts to the overall usage totals
func (l *PostgresLogger) accumulateOverallTokens(usage *AdvancedTokenUsage, log LogEntry) {
	usage.TotalTokens += log.TotalTokens
	usage.PromptTokens += log.PromptTokens
	usage.CompletionTokens += log.CompletionTokens
	usage.CachedTokens += log.CachedTokens
	usage.AudioTokens += log.AudioTokens
	usage.ReasoningTokens += log.ReasoningTokens
}

// accumulateModelTokens adds token counts to model-specific usage statistics
func (l *PostgresLogger) accumulateModelTokens(usage *AdvancedTokenUsage, log LogEntry) {
	if usage.ByModel[log.ModelName] == nil {
		usage.ByModel[log.ModelName] = &TokenUsageStats{}
	}
	modelUsage := usage.ByModel[log.ModelName]
	l.addTokensToStats(modelUsage, log)
}

// accumulateProviderTokens adds token counts to provider-specific usage statistics
func (l *PostgresLogger) accumulateProviderTokens(usage *AdvancedTokenUsage, log LogEntry) {
	if usage.ByProvider[log.ModelProvider] == nil {
		usage.ByProvider[log.ModelProvider] = &TokenUsageStats{}
	}
	providerUsage := usage.ByProvider[log.ModelProvider]
	l.addTokensToStats(providerUsage, log)
}

// addTokensToStats is a helper to add token counts from a log entry to token usage stats
func (l *PostgresLogger) addTokensToStats(stats *TokenUsageStats, log LogEntry) {
	stats.TotalTokens += log.TotalTokens
	stats.PromptTokens += log.PromptTokens
	stats.CompletionTokens += log.CompletionTokens
	stats.CachedTokens += log.CachedTokens
	stats.AudioTokens += log.AudioTokens
	stats.ReasoningTokens += log.ReasoningTokens
	stats.RequestCount++
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
