package logging

import (
	"encoding/json"
	"log"

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
	// Get user ID from middleware context (injected by auth middleware)
	userIDValue := ctx.UserValue("user_id")
	if userIDValue == nil {
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.SetBodyString(`{"error": "Not authenticated"}`)
		return
	}

	userID, ok := userIDValue.(uuid.UUID)
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Invalid user context"}`)
		return
	}

	// Get recent calls for this user
	recentCalls, err := h.plugin.GetRecentCallsForUser(userID, 10)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to fetch metrics"}`)
		log.Printf("Error fetching metrics for user %s: %v", userID, err)
		return
	}

	// Count total calls for this user
	var totalCalls int64
	h.db.Model(&LogEntry{}).Where("user_id = ?", userID).Count(&totalCalls)

	response := UserMetricsResponse{
		RecentCalls: recentCalls,
		TotalCalls:  int(totalCalls),
	}

	ctx.SetContentType("application/json")
	jsonResp, _ := json.Marshal(response)
	ctx.SetBody(jsonResp)
}