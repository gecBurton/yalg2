package middleware

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"bifrost-gov/internal/database"

	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/maximhq/bifrost/transports/bifrost-http/handlers"
	"github.com/valyala/fasthttp"
)

// LoggedCompletionHandler wraps Bifrost handlers with enhanced PostgreSQL logging
type LoggedCompletionHandler struct {
	handler *handlers.CompletionHandler
	logger  *database.PostgresLogger
}

// NewLoggedCompletionHandler creates a new logged completion handler
func NewLoggedCompletionHandler(handler *handlers.CompletionHandler, logger *database.PostgresLogger) *LoggedCompletionHandler {
	return &LoggedCompletionHandler{
		handler: handler,
		logger:  logger,
	}
}

// RegisterRoutes wraps the original handler routes with logging
func (l *LoggedCompletionHandler) RegisterRoutes(r *router.Router) {
	// Get the original routes by registering to a temporary router
	tempRouter := router.New()
	l.handler.RegisterRoutes(tempRouter)

	// Wrap the handlers with logging
	r.POST("/v1/chat/completions", l.wrapWithLogging(tempRouter, "/v1/chat/completions", "chat"))
	r.POST("/v1/text/completions", l.wrapWithLogging(tempRouter, "/v1/text/completions", "completion"))
}

// wrapWithLogging creates a logging wrapper for any handler
func (l *LoggedCompletionHandler) wrapWithLogging(tempRouter *router.Router, path, requestType string) fasthttp.RequestHandler {
	// Get the original handler
	originalHandler, _ := tempRouter.Lookup("POST", path, nil)

	return func(ctx *fasthttp.RequestCtx) {
		startTime := time.Now()
		requestID := fmt.Sprintf("req-%d", time.Now().UnixNano())

		// Extract request info for logging
		userID, model, provider := l.extractRequestInfo(ctx)
		
		// Capture request body and other context
		requestBody := ctx.PostBody()
		clientIP := string(ctx.Request.Header.Peek("X-Forwarded-For"))
		if clientIP == "" {
			clientIP = ctx.RemoteIP().String()
		}
		userAgent := string(ctx.Request.Header.Peek("User-Agent"))
		
		// Check if this is a streaming request
		isStreaming := l.isStreamingRequest(requestBody)
		
		// Set context values for potential use by Bifrost
		ctx.SetUserValue("request_id", requestID)
		ctx.SetUserValue("request_start_time", startTime)
		ctx.SetUserValue("client_ip", clientIP)
		ctx.SetUserValue("user_agent", userAgent)
		// request_body removed for security (sensitive data)
		ctx.SetUserValue("is_streaming", isStreaming)

		// Log streaming start if applicable
		if isStreaming {
			l.logger.LogStreamingUpdate(userID, requestID, "start", "")
		}

		// Call original handler (GitHub plugin will capture detailed logs automatically)
		originalHandler(ctx)

		// Extract response info for our PostgreSQL logging
		statusCode := ctx.Response.StatusCode()
		errorMessage := l.extractErrorMessage(ctx.Response.Body())
		responseTime := int(time.Since(startTime).Milliseconds())
		responseBody := ctx.Response.Body()
		
		// Extract token usage from response if available
		tokensUsed := l.extractTokenUsage(responseBody)

		// Use the enhanced LogAPIRequestWithContext method for our PostgreSQL logs
		l.logger.LogAPIRequestWithContext(userID, requestType, model, provider, statusCode, errorMessage, responseTime, tokensUsed, requestID, clientIP, userAgent, isStreaming, requestBody, responseBody)
	}
}

// extractRequestInfo extracts user ID and model info from request
func (l *LoggedCompletionHandler) extractRequestInfo(ctx *fasthttp.RequestCtx) (uuid.UUID, string, string) {
	// Extract user ID from auth middleware
	userID := uuid.Nil
	if userIDValue := ctx.UserValue("user_id"); userIDValue != nil {
		if uid, ok := userIDValue.(uuid.UUID); ok {
			userID = uid
		}
	}

	// Parse model from request body
	model, provider := "unknown", "unknown"
	var requestBody map[string]interface{}
	if err := json.Unmarshal(ctx.PostBody(), &requestBody); err == nil {
		if modelStr, ok := requestBody["model"].(string); ok {
			if parts := strings.Split(modelStr, "/"); len(parts) >= 2 {
				provider, model = parts[0], parts[1]
			} else {
				model = modelStr
			}
		}
	}

	return userID, model, provider
}

// isStreamingRequest checks if the request is for streaming
func (l *LoggedCompletionHandler) isStreamingRequest(requestBody []byte) bool {
	var reqMap map[string]interface{}
	if err := json.Unmarshal(requestBody, &reqMap); err == nil {
		if stream, ok := reqMap["stream"].(bool); ok {
			return stream
		}
	}
	return false
}

// extractTokenUsage extracts token usage from response body
func (l *LoggedCompletionHandler) extractTokenUsage(responseBody []byte) int {
	var respMap map[string]interface{}
	if err := json.Unmarshal(responseBody, &respMap); err == nil {
		if usage, ok := respMap["usage"].(map[string]interface{}); ok {
			if total, ok := usage["total_tokens"].(float64); ok {
				return int(total)
			}
		}
	}
	return 0
}

// extractErrorMessage extracts error message from response body
func (l *LoggedCompletionHandler) extractErrorMessage(responseBody []byte) string {
	if len(responseBody) == 0 {
		return ""
	}

	var respMap map[string]interface{}
	if err := json.Unmarshal(responseBody, &respMap); err == nil {
		if errMsg, ok := respMap["error"].(string); ok {
			return errMsg
		}
		if errMap, ok := respMap["error"].(map[string]interface{}); ok {
			if msg, ok := errMap["message"].(string); ok {
				return msg
			}
		}
	}
	return ""
}