package handlers

import (
	"encoding/json"

	"bifrost-gov/internal/database"

	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
)

// LoggingHandler handles logging-related HTTP routes using the PostgreSQL logger
type LoggingHandler struct {
	logger *database.PostgresLogger
}

// UserMetricsResponse represents the response format for user metrics
type UserMetricsResponse struct {
	RecentCalls []database.LogEntry `json:"recent_calls"`
	TotalCalls  int64               `json:"total_calls"`
}

// NewLoggingHandler creates a new logging handler
func NewLoggingHandler(postgresLogger *database.PostgresLogger) *LoggingHandler {
	return &LoggingHandler{
		logger: postgresLogger,
	}
}

// RegisterRoutes registers all logging-related routes
func (h *LoggingHandler) RegisterRoutes(r *router.Router) {
	r.GET("/metrics", h.metricsHandler)
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
	recentCalls, err := h.logger.GetRecentCallsForUser(userID, 10)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to fetch recent calls"}`)
		return
	}

	// Count total calls for this user
	totalCalls, err := h.logger.GetTotalCallsForUser(userID)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to fetch total calls"}`)
		return
	}

	response := UserMetricsResponse{
		RecentCalls: recentCalls,
		TotalCalls:  totalCalls,
	}

	ctx.SetContentType("application/json")
	jsonResp, _ := json.Marshal(response)
	ctx.SetBody(jsonResp)
}
