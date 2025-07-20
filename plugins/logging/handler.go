package logging

import (
	"encoding/json"
	"log"
	"time"

	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
	"gorm.io/gorm"
)

// LoggingHandler handles logging-related HTTP routes
type LoggingHandler struct {
	plugin *SecureLoggingPlugin
	db     *gorm.DB
}

// NewLoggingHandler creates a new logging handler
func NewLoggingHandler(db *gorm.DB) *LoggingHandler {
	return &LoggingHandler{
		plugin: NewSecureLoggingPlugin(db),
		db:     db,
	}
}

// RegisterRoutes registers all logging-related routes
func (h *LoggingHandler) RegisterRoutes(r *router.Router) {
	r.GET("/metrics", h.metricsHandler)
}

// UserMetricsResponse represents the metrics response for a user
type UserMetricsResponse struct {
	RecentCalls []LogEntry `json:"recent_calls"`
	TotalCalls  int        `json:"total_calls"`
}

// metricsHandler returns metrics for the authenticated user
func (h *LoggingHandler) metricsHandler(ctx *fasthttp.RequestCtx) {
	// Get user ID from session cookie by looking up in sessions table
	sessionID := string(ctx.Request.Header.Cookie("session"))
	if sessionID == "" {
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.SetBodyString(`{"error": "Not authenticated"}`)
		return
	}

	// Query the sessions table directly to get user ID
	// Define a Session struct that matches the auth plugin's Session table
	type Session struct {
		ID        string    `gorm:"primaryKey"`
		UserID    uuid.UUID `gorm:"type:uuid;index"`
		ExpiresAt time.Time `gorm:"index"`
	}

	var session Session
	err := h.db.Where("id = ? AND expires_at > ?", sessionID, time.Now()).First(&session).Error
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.SetBodyString(`{"error": "Invalid or expired session"}`)
		log.Printf("Session lookup failed for ID %s: %v", sessionID, err)
		return
	}

	// Get recent calls for this user
	recentCalls, err := h.plugin.GetRecentCallsForUser(session.UserID, 10)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to fetch metrics"}`)
		log.Printf("Error fetching metrics for user %d: %v", session.UserID, err)
		return
	}

	// Count total calls for this user
	var totalCalls int64
	h.db.Model(&LogEntry{}).Where("user_id = ?", session.UserID).Count(&totalCalls)

	response := UserMetricsResponse{
		RecentCalls: recentCalls,
		TotalCalls:  int(totalCalls),
	}

	ctx.SetContentType("application/json")
	jsonResp, _ := json.Marshal(response)
	ctx.SetBody(jsonResp)
}