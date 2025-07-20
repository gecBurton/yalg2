package logging

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	"gorm.io/gorm"
)

// SecureLoggingPlugin implements secure logging with user context
type SecureLoggingPlugin struct {
	db *gorm.DB
}

// NewSecureLoggingPlugin creates a new secure logging plugin
func NewSecureLoggingPlugin(db *gorm.DB) *SecureLoggingPlugin {
	if db != nil {
		// Auto-migrate the LogEntry table
		db.AutoMigrate(&LogEntry{})
	}

	return &SecureLoggingPlugin{
		db: db,
	}
}

// GetName returns the name of the plugin
func (p *SecureLoggingPlugin) GetName() string {
	return "SecureLoggingPlugin"
}

// PreHook is called before a request is processed by a provider
func (p *SecureLoggingPlugin) PreHook(ctx *context.Context, req *schemas.BifrostRequest) (*schemas.BifrostRequest, *schemas.PluginShortCircuit, error) {
	// Store request start time in context for response time calculation
	startTime := time.Now()
	*ctx = context.WithValue(*ctx, "request_start_time", startTime)

	// Generate unique request ID
	requestID := fmt.Sprintf("%d-%s", startTime.UnixNano(), req.Model)
	*ctx = context.WithValue(*ctx, "request_id", requestID)

	return req, nil, nil
}

// PostHook is called after a response is received from a provider
func (p *SecureLoggingPlugin) PostHook(ctx *context.Context, result *schemas.BifrostResponse, err *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError, error) {
	if p.db == nil {
		return result, err, nil
	}

	// Extract timing information
	startTime, _ := (*ctx).Value("request_start_time").(time.Time)
	requestID, _ := (*ctx).Value("request_id").(string)
	responseTime := int(time.Since(startTime).Milliseconds())

	// Extract user ID from context (set by AuthCompletionHandler)
	var userID *uuid.UUID
	if userIDValue := (*ctx).Value("user_id"); userIDValue != nil {
		if uid, ok := userIDValue.(uuid.UUID); ok {
			userID = &uid
			log.Printf("Logging plugin found user ID in context: %s", uid)
		} else {
			log.Printf("Logging plugin found user_id but wrong type: %T = %v", userIDValue, userIDValue)
		}
	} else {
		log.Printf("Logging plugin: no user_id found in context")
	}

	// Create log entry
	logEntry := &LogEntry{
		UserID:         userID,
		RequestID:      requestID,
		ResponseTimeMs: responseTime,
		CreatedAt:      time.Now(),
	}

	// Extract request information
	if reqValue := (*ctx).Value("bifrost_request"); reqValue != nil {
		if req, ok := reqValue.(*schemas.BifrostRequest); ok {
			logEntry.ModelProvider = string(req.Provider)
			logEntry.ModelName = req.Model
			logEntry.RequestType = "chat" // Default, could be extracted from request type
		}
	}

	// Handle response or error
	if result != nil {
		logEntry.StatusCode = 200
		if result.Usage != nil {
			logEntry.TokensUsed = result.Usage.TotalTokens
		}
	} else if err != nil {
		if err.StatusCode != nil {
			logEntry.StatusCode = *err.StatusCode
		} else {
			logEntry.StatusCode = 500
		}
		logEntry.ErrorMessage = err.Error.Message
	}

	// Store log entry in database
	if createErr := p.db.Create(logEntry).Error; createErr != nil {
		log.Printf("Warning: failed to create log entry: %v", createErr)
	} else {
		log.Printf("Successfully created log entry: UserID=%v, Model=%s, Provider=%s, Tokens=%d", 
			logEntry.UserID, logEntry.ModelName, logEntry.ModelProvider, logEntry.TokensUsed)
	}

	return result, err, nil
}

// GetRecentCallsForUser retrieves the most recent calls for a specific user
func (p *SecureLoggingPlugin) GetRecentCallsForUser(userID uuid.UUID, limit int) ([]LogEntry, error) {
	if p.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	var entries []LogEntry
	err := p.db.Preload("User").
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).
		Find(&entries).Error

	return entries, err
}

// Cleanup is called on bifrost shutdown
func (p *SecureLoggingPlugin) Cleanup() error {
	// No cleanup needed - database connection is managed elsewhere
	return nil
}