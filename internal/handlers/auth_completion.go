package handlers

import (
	"context"
	"encoding/json"
	"log"
	"strings"

	"bifrost-gov/plugins/auth"
	"github.com/fasthttp/router"
	"github.com/google/uuid"
	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/bifrost-http/handlers"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
	"gorm.io/gorm"
)

// AuthCompletionHandler wraps the standard completion handler with JWT authentication
type AuthCompletionHandler struct {
	client     *bifrost.Bifrost
	logger     schemas.Logger
	authPlugin *auth.AuthPlugin
}

// NewAuthCompletionHandler creates a new authenticated completion handler
func NewAuthCompletionHandler(client *bifrost.Bifrost, logger schemas.Logger, db *gorm.DB) (*AuthCompletionHandler, error) {
	// Create auth plugin for token validation
	oidcConfig := &auth.OIDCConfig{
		IssuerURL: "http://localhost:5556",
		ClientID:  "bifrost-client",
	}
	
	authPlugin, err := auth.NewAuthPluginWithDB(oidcConfig, db)
	if err != nil {
		return nil, err
	}
	
	return &AuthCompletionHandler{
		client:     client,
		logger:     logger,
		authPlugin: authPlugin,
	}, nil
}

// RegisterRoutes registers completion routes with authentication
func (h *AuthCompletionHandler) RegisterRoutes(r *router.Router) {
	r.POST("/v1/chat/completions", h.AuthenticatedChatCompletion)
	r.POST("/v1/text/completions", h.AuthenticatedTextCompletion)
}

// CompletionRequest represents a request for either text or chat completion
type CompletionRequest struct {
	Model     string                   `json:"model"`     
	Messages  []schemas.BifrostMessage `json:"messages"`  
	Text      string                   `json:"text"`      
	Params    *schemas.ModelParameters `json:"params"`    
	Fallbacks []string                 `json:"fallbacks"` 
	Stream    *bool                    `json:"stream"`    
}

// validateJWTAndGetUserID validates JWT token and returns user ID
func (h *AuthCompletionHandler) validateJWTAndGetUserID(ctx *fasthttp.RequestCtx) (uuid.UUID, error) {
	// Extract Authorization header
	authHeader := string(ctx.Request.Header.Peek("Authorization"))
	if authHeader == "" {
		return uuid.Nil, nil // No auth header
	}
	
	// Extract token
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == authHeader {
		return uuid.Nil, nil // No Bearer prefix
	}
	
	// Verify the token
	tempCtx := context.Background()
	idToken, err := h.authPlugin.GetVerifier().Verify(tempCtx, token)
	if err != nil {
		return uuid.Nil, err
	}
	
	// Extract claims
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return uuid.Nil, err
	}
	
	// Get user subject
	sub, ok := claims["sub"].(string)
	if !ok {
		return uuid.Nil, err
	}
	
	// Find user in database
	user := &auth.User{}
	err = h.authPlugin.GetDB().Where("sub = ?", sub).First(user).Error
	if err != nil {
		return uuid.Nil, err
	}
	
	return user.ID, nil
}

// AuthenticatedChatCompletion handles authenticated chat completion requests
func (h *AuthCompletionHandler) AuthenticatedChatCompletion(ctx *fasthttp.RequestCtx) {
	h.handleAuthenticatedCompletion(ctx, "chat")
}

// AuthenticatedTextCompletion handles authenticated text completion requests  
func (h *AuthCompletionHandler) AuthenticatedTextCompletion(ctx *fasthttp.RequestCtx) {
	h.handleAuthenticatedCompletion(ctx, "text")
}

// handleAuthenticatedCompletion processes completion requests with authentication
func (h *AuthCompletionHandler) handleAuthenticatedCompletion(ctx *fasthttp.RequestCtx, completionType string) {
	// Validate JWT token first
	userID, err := h.validateJWTAndGetUserID(ctx)
	if err != nil {
		handlers.SendError(ctx, fasthttp.StatusUnauthorized, "Invalid authentication token", h.logger)
		return
	}
	
	log.Printf("Authenticated API request for user ID: %s", userID)
	
	// Parse request
	var req CompletionRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		handlers.SendError(ctx, fasthttp.StatusBadRequest, "Invalid request format", h.logger)
		return
	}
	
	if req.Model == "" {
		handlers.SendError(ctx, fasthttp.StatusBadRequest, "Model is required", h.logger)
		return
	}
	
	// Parse model format
	model := strings.SplitN(req.Model, "/", 2)
	if len(model) < 2 {
		handlers.SendError(ctx, fasthttp.StatusBadRequest, "Model must be in format 'provider/model'", h.logger)
		return
	}
	
	provider := model[0]
	modelName := model[1]
	
	// Build fallbacks
	fallbacks := make([]schemas.Fallback, len(req.Fallbacks))
	for i, fallback := range req.Fallbacks {
		fallbackModel := strings.Split(fallback, "/")
		if len(fallbackModel) != 2 {
			handlers.SendError(ctx, fasthttp.StatusBadRequest, "Fallback must be in format 'provider/model'", h.logger)
			return
		}
		fallbacks[i] = schemas.Fallback{
			Provider: schemas.ModelProvider(fallbackModel[0]),
			Model:    fallbackModel[1],
		}
	}
	
	// Create BifrostRequest
	bifrostReq := &schemas.BifrostRequest{
		Model:     modelName,
		Provider:  schemas.ModelProvider(provider),
		Params:    req.Params,
		Fallbacks: fallbacks,
	}
	
	// Set input based on completion type
	if completionType == "text" {
		if req.Text == "" {
			handlers.SendError(ctx, fasthttp.StatusBadRequest, "Text is required for text completion", h.logger)
			return
		}
		bifrostReq.Input = schemas.RequestInput{
			TextCompletionInput: &req.Text,
		}
	} else { // chat
		if len(req.Messages) == 0 {
			handlers.SendError(ctx, fasthttp.StatusBadRequest, "Messages array is required for chat completion", h.logger)
			return
		}
		bifrostReq.Input = schemas.RequestInput{
			ChatCompletionInput: &req.Messages,
		}
	}
	
	// Convert context and add user ID
	bifrostCtx := lib.ConvertToBifrostContext(ctx)
	if bifrostCtx == nil {
		handlers.SendError(ctx, fasthttp.StatusInternalServerError, "Failed to convert context", h.logger)
		return
	}
	
	// Add user ID to context for logging plugin
	*bifrostCtx = context.WithValue(*bifrostCtx, "user_id", userID)
	*bifrostCtx = context.WithValue(*bifrostCtx, "user_sub", "authenticated-user")
	
	// Add request information to context for logging plugin
	*bifrostCtx = context.WithValue(*bifrostCtx, "bifrost_request", bifrostReq)
	
	// Call Bifrost
	var resp *schemas.BifrostResponse
	var bifrostErr *schemas.BifrostError
	
	if completionType == "text" {
		resp, bifrostErr = h.client.TextCompletionRequest(*bifrostCtx, bifrostReq)
	} else {
		resp, bifrostErr = h.client.ChatCompletionRequest(*bifrostCtx, bifrostReq)
	}
	
	// Handle response
	if bifrostErr != nil {
		handlers.SendBifrostError(ctx, bifrostErr, h.logger)
		return
	}
	
	// Send successful response
	handlers.SendJSON(ctx, resp, h.logger)
}