package middleware

import (
	"context"
	"fmt"
	"log"
	"strings"

	"bifrost-gov/plugins/auth"
	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
	"gorm.io/gorm"
)

// AuthConfig defines which routes require authentication
type AuthConfig struct {
	// Routes that require authentication (supports wildcards)
	ProtectedRoutes []string
	// Routes that are always public (supports wildcards)
	PublicRoutes []string
}

// AuthMiddleware handles JWT authentication for protected routes
type AuthMiddleware struct {
	config     *AuthConfig
	authPlugin *auth.AuthPlugin
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(config *AuthConfig, db *gorm.DB) (*AuthMiddleware, error) {
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
		config:     config,
		authPlugin: authPlugin,
	}, nil
}

// DefaultAuthConfig returns a sensible default configuration
func DefaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		ProtectedRoutes: []string{
			"/v1/*",           // All API endpoints
			"/metrics",        // Metrics endpoint (user-specific)
			"/api/*",          // Internal API endpoints
		},
		PublicRoutes: []string{
			"/auth/*",         // Authentication flows
			"/",               // UI root
			"/ui/*",           // UI assets
			"/app/*",          // UI routes
			"/static/*",       // Static assets
		},
	}
}

// matchesPattern checks if a path matches a pattern (supports wildcards)
func matchesPattern(path, pattern string) bool {
	if pattern == path {
		return true
	}
	
	// Handle wildcard patterns
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	}
	
	return false
}

// needsAuthentication determines if a route requires authentication
func (m *AuthMiddleware) needsAuthentication(path string) bool {
	// First check if explicitly public
	for _, publicRoute := range m.config.PublicRoutes {
		if matchesPattern(path, publicRoute) {
			return false
		}
	}
	
	// Then check if explicitly protected
	for _, protectedRoute := range m.config.ProtectedRoutes {
		if matchesPattern(path, protectedRoute) {
			return true
		}
	}
	
	// Default to not requiring auth if not explicitly configured
	return false
}

// validateJWTAndGetUserID validates JWT token and returns user ID
func (m *AuthMiddleware) validateJWTAndGetUserID(ctx *fasthttp.RequestCtx) (uuid.UUID, error) {
	// Extract Authorization header
	authHeader := string(ctx.Request.Header.Peek("Authorization"))
	if authHeader == "" {
		return uuid.Nil, fmt.Errorf("missing Authorization header")
	}
	
	// Extract token
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == authHeader {
		return uuid.Nil, fmt.Errorf("invalid Authorization header format")
	}
	
	// Verify the token
	tempCtx := context.Background()
	idToken, err := m.authPlugin.GetVerifier().Verify(tempCtx, token)
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
		return uuid.Nil, fmt.Errorf("invalid token subject")
	}
	
	// Find user in database
	user := &auth.User{}
	err = m.authPlugin.GetDB().Where("sub = ?", sub).First(user).Error
	if err != nil {
		return uuid.Nil, err
	}
	
	return user.ID, nil
}

// Handler creates a FastHTTP middleware handler
func (m *AuthMiddleware) Handler(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		path := string(ctx.Path())
		
		// Check if this route needs authentication
		if !m.needsAuthentication(path) {
			// Route is public, continue without auth
			next(ctx)
			return
		}
		
		// Route is protected, validate JWT
		userID, err := m.validateJWTAndGetUserID(ctx)
		if err != nil {
			log.Printf("Authentication failed for path %s: %v", path, err)
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			ctx.SetBodyString(`{"error":"Authentication required"}`)
			ctx.SetContentType("application/json")
			return
		}
		
		// Authentication successful, inject user context
		log.Printf("Authenticated request for path %s, user ID: %s", path, userID)
		
		// Store user information in request context for downstream handlers
		ctx.SetUserValue("user_id", userID)
		ctx.SetUserValue("authenticated", true)
		
		// Continue to next handler
		next(ctx)
	}
}