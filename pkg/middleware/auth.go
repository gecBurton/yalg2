package middleware

import (
	"context"
	"log"
	"strings"

	"bifrost-gov/plugins/auth"
	"github.com/valyala/fasthttp"
	"gorm.io/gorm"
)

// AuthMiddleware validates JWT tokens and sets user context
type AuthMiddleware struct {
	authPlugin *auth.AuthPlugin
}

// NewAuthMiddleware creates a new auth middleware
func NewAuthMiddleware(db *gorm.DB) (*AuthMiddleware, error) {
	// Create auth plugin for token validation
	oidcConfig := &auth.OIDCConfig{
		IssuerURL: "http://localhost:5556",
		ClientID:  "bifrost-client",
	}
	
	authPlugin, err := auth.NewAuthPluginWithDB(oidcConfig, db)
	if err != nil {
		return nil, err
	}
	
	return &AuthMiddleware{
		authPlugin: authPlugin,
	}, nil
}

// ValidateJWTAndSetUserContext validates the JWT token and returns user ID
func (m *AuthMiddleware) ValidateJWTAndSetUserContext(ctx *fasthttp.RequestCtx) (uint, error) {
	// Extract Authorization header
	authHeader := string(ctx.Request.Header.Peek("Authorization"))
	if authHeader == "" {
		return 0, nil // No auth header, return 0 user ID
	}
	
	// Extract token
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == authHeader {
		return 0, nil // No Bearer prefix
	}
	
	log.Printf("Validating JWT token for API request")
	
	// Create temporary context for token validation
	tempCtx := context.Background()
	
	// Verify the token
	idToken, err := m.authPlugin.GetVerifier().Verify(tempCtx, token)
	if err != nil {
		log.Printf("JWT token validation failed: %v", err)
		return 0, err
	}
	
	// Extract claims
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		log.Printf("Failed to extract token claims: %v", err)
		return 0, err
	}
	
	// Get user from claims
	sub, ok := claims["sub"].(string)
	if !ok {
		log.Printf("Missing subject claim in token")
		return 0, err
	}
	
	// Find user in database by subject
	user := &auth.User{}
	err = m.authPlugin.GetDB().Where("sub = ?", sub).First(user).Error
	if err != nil {
		log.Printf("User not found for subject %s: %v", sub, err)
		return 0, err
	}
	
	log.Printf("JWT validation successful for user ID %d", user.ID)
	return user.ID, nil
}