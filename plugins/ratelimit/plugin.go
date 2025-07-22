package ratelimit

import (
	"bifrost-gov/internal/database"
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	"gorm.io/gorm"
)

// RateLimitPlugin implements per-user rate limiting using database-based request counting
type RateLimitPlugin struct {
	db *gorm.DB
}

// NewRateLimitPlugin creates a new rate limiting plugin
func NewRateLimitPlugin(db *gorm.DB) *RateLimitPlugin {
	return &RateLimitPlugin{
		db: db,
	}
}

// GetName returns the name of the plugin
func (p *RateLimitPlugin) GetName() string {
	return "RateLimitPlugin"
}

// PreHook checks rate limits before request processing
func (p *RateLimitPlugin) PreHook(ctx *context.Context, req *schemas.BifrostRequest) (*schemas.BifrostRequest, *schemas.PluginShortCircuit, error) {
	if p.db == nil {
		return req, nil, nil // No database, skip rate limiting
	}

	// Extract user ID from context (set by auth completion handler)
	userIDValue := (*ctx).Value("user_id")
	if userIDValue == nil {
		return req, nil, nil // No user context, skip rate limiting
	}

	userID, ok := userIDValue.(uuid.UUID)
	if !ok {
		return req, nil, nil // Invalid user ID type, skip rate limiting
	}

	// Get user's rate limit from database
	var user database.User
	if err := p.db.First(&user, userID).Error; err != nil {
		return req, nil, nil // User not found, skip rate limiting
	}

	// Check current request count in the last minute
	oneMinuteAgo := time.Now().Add(-time.Minute)
	var requestCount int64

	err := p.db.Table("log_entries").
		Where("user_id = ? AND created_at > ?", userID, oneMinuteAgo).
		Count(&requestCount).Error

	if err != nil {
		// Log error but don't fail the request
		return req, nil, fmt.Errorf("failed to check rate limit: %w", err)
	}

	// Check if user has exceeded their rate limit
	if int(requestCount) >= user.MaxRequestsPerMinute {
		// Return error to block the request
		return req, nil, fmt.Errorf("rate limit exceeded: %d requests in the last minute (limit: %d)", requestCount, user.MaxRequestsPerMinute)
	}

	return req, nil, nil
}

// PostHook is called after a response is received from a provider
func (p *RateLimitPlugin) PostHook(ctx *context.Context, result *schemas.BifrostResponse, err *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError, error) {
	// No post-processing needed for rate limiting
	return result, err, nil
}

// Cleanup is called on bifrost shutdown
func (p *RateLimitPlugin) Cleanup() error {
	// No cleanup needed - database connection is managed elsewhere
	return nil
}

// GetUserRateLimit returns the current rate limit for a user
func (p *RateLimitPlugin) GetUserRateLimit(userID uuid.UUID) (int, error) {
	if p.db == nil {
		return 0, fmt.Errorf("database not available")
	}

	var user database.User
	if err := p.db.First(&user, userID).Error; err != nil {
		return 0, err
	}

	return user.MaxRequestsPerMinute, nil
}

// GetUserRequestCount returns the number of requests made by a user in the last minute
func (p *RateLimitPlugin) GetUserRequestCount(userID uuid.UUID) (int64, error) {
	if p.db == nil {
		return 0, fmt.Errorf("database not available")
	}

	oneMinuteAgo := time.Now().Add(-time.Minute)
	var count int64

	err := p.db.Table("log_entries").
		Where("user_id = ? AND created_at > ?", userID, oneMinuteAgo).
		Count(&count).Error

	return count, err
}

// UpdateUserRateLimit updates the rate limit for a specific user
func (p *RateLimitPlugin) UpdateUserRateLimit(userID uuid.UUID, newLimit int) error {
	if p.db == nil {
		return fmt.Errorf("database not available")
	}

	return p.db.Model(&database.User{}).Where("id = ?", userID).Update("max_requests_per_minute", newLimit).Error
}
