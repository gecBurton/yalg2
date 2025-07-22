package database

import (
	"time"

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

// LogEntry represents a log entry stored in PostgreSQL
type LogEntry struct {
	ID             uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID         *uuid.UUID `json:"user_id" gorm:"type:uuid;index"` // Foreign key to users table
	User           *User      `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Level          string     `json:"level" gorm:"index"`      // DEBUG, INFO, WARN, ERROR
	Message        string     `json:"message"`                 // Log message
	RequestID      string     `json:"request_id" gorm:"index"` // Unique request identifier
	ModelProvider  string     `json:"model_provider"`          // Which AI provider was used
	ModelName      string     `json:"model_name"`              // Model name (e.g., gpt-4, claude-3)
	TokensUsed     int        `json:"tokens_used"`             // Number of tokens consumed
	ResponseTimeMs int        `json:"response_time_ms"`        // Response time in milliseconds
	StatusCode     int        `json:"status_code"`             // HTTP status code
	ErrorMessage   string     `json:"error_message,omitempty"` // Error message if request failed
	RequestType    string     `json:"request_type"`            // Type: "chat", "completion", "embedding", etc.
	IPAddress      string     `json:"ip_address,omitempty"`    // Client IP (optional)
	UserAgent      string     `json:"user_agent,omitempty"`    // Client user agent (optional)
	CreatedAt      time.Time  `json:"created_at"`
}

// PostgresLogger implements Bifrost's Logger interface and stores logs in PostgreSQL
type PostgresLogger struct {
	db    *gorm.DB
	level schemas.LogLevel
}

// NewPostgresLogger creates a new PostgreSQL logger
func NewPostgresLogger(db *gorm.DB, level schemas.LogLevel) (*PostgresLogger, error) {
	// Auto-migrate the log entry table
	if err := db.AutoMigrate(&LogEntry{}); err != nil {
		return nil, err
	}

	return &PostgresLogger{
		db:    db,
		level: level,
	}, nil
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

// logEntry creates and stores a log entry
func (l *PostgresLogger) logEntry(level schemas.LogLevel, message string, ctx *context.Context) {
	entry := &LogEntry{
		Level:     levelToString(level),
		Message:   message,
		CreatedAt: time.Now(),
	}

	// Extract context information if available
	if ctx != nil {
		l.enrichFromContext(entry, *ctx)
	}

	// Store in database
	if err := l.db.Create(entry).Error; err != nil {
		// Fallback to standard logging if database write fails
		log.Printf("[%s] %s (DB write failed: %v)", entry.Level, message, err)
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

	// Extract request information if available
	if reqValue := ctx.Value("bifrost_request"); reqValue != nil {
		if req, ok := reqValue.(*schemas.BifrostRequest); ok {
			entry.ModelProvider = string(req.Provider)
			entry.ModelName = req.Model
			entry.RequestType = "completion" // Could be more specific based on request type
		}
	}

	// Extract response information if available
	if respValue := ctx.Value("bifrost_response"); respValue != nil {
		if resp, ok := respValue.(*schemas.BifrostResponse); ok {
			entry.StatusCode = 200
			if resp.Usage != nil {
				entry.TokensUsed = resp.Usage.TotalTokens
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

// LogAPIRequest logs an API request directly (for all requests, successful or not)
func (l *PostgresLogger) LogAPIRequest(userID uuid.UUID, requestType, model, provider string, statusCode int, errorMessage string, responseTimeMs int, tokensUsed int) {
	entry := &LogEntry{
		UserID:         &userID,
		Level:          "INFO",
		Message:        fmt.Sprintf("API request: %s", requestType),
		RequestID:      fmt.Sprintf("api-%d", time.Now().UnixNano()),
		ModelProvider:  provider,
		ModelName:      model,
		TokensUsed:     tokensUsed,
		ResponseTimeMs: responseTimeMs,
		StatusCode:     statusCode,
		ErrorMessage:   errorMessage,
		RequestType:    requestType,
		CreatedAt:      time.Now(),
	}

	// Store in database
	if err := l.db.Create(entry).Error; err != nil {
		log.Printf("[PostgresLogger] Failed to log API request: %v", err)
	}
}
