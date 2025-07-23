package middleware

import (
	"encoding/json"
	"strconv"
	"time"

	"bifrost-gov/internal/database"
	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
)

// LoggingHandler provides REST API access to logging data with
// advanced LLMUsage tracking and basic metrics from PostgreSQL
type LoggingHandler struct {
	logger *database.PostgresLogger
}

// NewLoggingHandler creates a new unified logging handler
func NewLoggingHandler(logger *database.PostgresLogger) *LoggingHandler {
	return &LoggingHandler{
		logger: logger,
	}
}

// RegisterRoutes registers all logging routes (basic + enhanced)
func (h *LoggingHandler) RegisterRoutes(r *router.Router) {
	// Legacy endpoint for backward compatibility
	r.GET("/metrics", h.getBasicMetrics)
	
	// Enhanced endpoints with advanced token tracking
	r.GET("/api/enhanced-logs", h.getEnhancedLogs)
	r.GET("/api/token-usage", h.getDetailedTokenUsage)
	r.GET("/api/token-usage/summary", h.getTokenUsageSummary)
}

// getEnhancedLogs returns enhanced logs with GitHub plugin data and user context
func (h *LoggingHandler) getEnhancedLogs(ctx *fasthttp.RequestCtx) {
	// Get user ID from auth middleware
	userIDValue := ctx.UserValue("user_id")
	if userIDValue == nil {
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.SetBodyString(`{"error": "User not authenticated"}`)
		return
	}

	userID, ok := userIDValue.(uuid.UUID)
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid user ID"}`)
		return
	}

	// Get limit parameter (default: 50)
	limitStr := string(ctx.QueryArgs().Peek("limit"))
	limit := 50
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	// Get enhanced logs
	logs, err := h.logger.GetEnhancedLogsForUser(userID, limit)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to retrieve enhanced logs"}`)
		return
	}

	// Return JSON response
	ctx.SetContentType("application/json")
	if err := json.NewEncoder(ctx).Encode(map[string]interface{}{
		"logs":  logs,
		"count": len(logs),
	}); err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to encode response"}`)
	}
}

// getDetailedTokenUsage returns comprehensive token usage statistics
func (h *LoggingHandler) getDetailedTokenUsage(ctx *fasthttp.RequestCtx) {
	// Get user ID from auth middleware
	userIDValue := ctx.UserValue("user_id")
	if userIDValue == nil {
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.SetBodyString(`{"error": "User not authenticated"}`)
		return
	}

	userID, ok := userIDValue.(uuid.UUID)
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid user ID"}`)
		return
	}

	// Get time range parameter (default: 7 days)
	daysStr := string(ctx.QueryArgs().Peek("days"))
	days := 7
	if daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 365 {
			days = d
		}
	}
	timeRange := time.Duration(days) * 24 * time.Hour

	// Get detailed token usage
	usage, err := h.logger.GetAdvancedTokenUsageForUser(userID, timeRange)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to retrieve token usage"}`)
		return
	}

	// Return JSON response
	ctx.SetContentType("application/json")
	if err := json.NewEncoder(ctx).Encode(map[string]interface{}{
		"usage":      usage,
		"time_range": map[string]interface{}{
			"days":       days,
			"start_date": time.Now().Add(-timeRange).Format("2006-01-02"),
			"end_date":   time.Now().Format("2006-01-02"),
		},
	}); err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to encode response"}`)
	}
}

// getTokenUsageSummary returns a simplified token usage summary
func (h *LoggingHandler) getTokenUsageSummary(ctx *fasthttp.RequestCtx) {
	// Get user ID from auth middleware
	userIDValue := ctx.UserValue("user_id")
	if userIDValue == nil {
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.SetBodyString(`{"error": "User not authenticated"}`)
		return
	}

	userID, ok := userIDValue.(uuid.UUID)
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid user ID"}`)
		return
	}

	// Get usage for different time periods
	timeRanges := map[string]time.Duration{
		"today":      24 * time.Hour,
		"week":       7 * 24 * time.Hour,
		"month":      30 * 24 * time.Hour,
		"total":      365 * 24 * time.Hour, // Up to 1 year
	}

	summary := make(map[string]interface{})
	for period, duration := range timeRanges {
		usage, err := h.logger.GetAdvancedTokenUsageForUser(userID, duration)
		if err != nil {
			continue // Skip periods with errors
		}

		summary[period] = map[string]interface{}{
			"total_tokens":      usage.TotalTokens,
			"prompt_tokens":     usage.PromptTokens,
			"completion_tokens": usage.CompletionTokens,
			"models_used":       len(usage.ByModel),
			"providers_used":    len(usage.ByProvider),
		}
	}

	// Return JSON response
	ctx.SetContentType("application/json")
	if err := json.NewEncoder(ctx).Encode(map[string]interface{}{
		"summary":    summary,
		"updated_at": time.Now().Format(time.RFC3339),
	}); err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to encode response"}`)
	}
}

// getBasicMetrics provides basic metrics for backward compatibility (legacy /metrics endpoint)
func (h *LoggingHandler) getBasicMetrics(ctx *fasthttp.RequestCtx) {
	// Get user ID from auth middleware
	userIDValue := ctx.UserValue("user_id")
	if userIDValue == nil {
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.SetBodyString(`{"error": "Not authenticated"}`)
		return
	}

	userID, ok := userIDValue.(uuid.UUID)
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error": "Invalid user ID"}`)
		return
	}

	// Get recent calls and total count
	recentCalls, err := h.logger.GetRecentCallsForUser(userID, 10)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to get recent calls"}`)
		return
	}

	totalCalls, err := h.logger.GetTotalCallsForUser(userID)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to get total calls"}`)
		return
	}

	// Return legacy format for backward compatibility
	type UserMetricsResponse struct {
		RecentCalls []database.LogEntry `json:"recent_calls"`
		TotalCalls  int64               `json:"total_calls"`
	}

	response := UserMetricsResponse{
		RecentCalls: recentCalls,
		TotalCalls:  totalCalls,
	}

	ctx.SetContentType("application/json")
	if err := json.NewEncoder(ctx).Encode(response); err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error": "Failed to encode response"}`)
	}
}