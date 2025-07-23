package middleware

import (
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
)

// hasJWTHeader checks if request has Authorization header with Bearer token
func hasJWTHeader(ctx *fasthttp.RequestCtx) bool {
	authHeader := ctx.Request.Header.Peek("Authorization")
	return len(authHeader) > 0 && strings.HasPrefix(string(authHeader), "Bearer ")
}

// needsAuthentication determines if a route requires authentication
func (m *AuthMiddleware) needsAuthentication(path string) bool {
	// Fast path: exact lookups first
	if m.config.ExactPublic[path] {
		return false
	}
	if m.config.ExactProtected[path] {
		return true
	}
	
	// Fast path: common API prefixes
	if strings.HasPrefix(path, "/v1/") || strings.HasPrefix(path, "/api/") {
		return true
	}
	if strings.HasPrefix(path, "/auth/") || strings.HasPrefix(path, "/ui/") || 
	   strings.HasPrefix(path, "/app/") || strings.HasPrefix(path, "/static/") {
		return false
	}
	
	// Fallback to pattern matching only if needed
	for _, publicRoute := range m.config.PublicRoutes {
		if matchesPattern(path, publicRoute) {
			return false
		}
	}

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

	// Verify the token and get claims
	claims, err := m.service.VerifyIDToken(token)
	if err != nil {
		return uuid.Nil, err
	}

	// Get user subject
	sub, ok := claims["sub"].(string)
	if !ok {
		return uuid.Nil, fmt.Errorf("invalid token subject")
	}

	// Find or create user in database
	user, err := m.service.FindOrCreateUser(sub, claims)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to find/create user: %w", err)
	}

	return user.ID, nil
}

// validateSessionAndGetUserID validates session cookie and returns user ID
func (m *AuthMiddleware) validateSessionAndGetUserID(ctx *fasthttp.RequestCtx) (uuid.UUID, error) {
	// Extract session cookie
	sessionCookie := ctx.Request.Header.Cookie("session")
	if len(sessionCookie) == 0 {
		return uuid.Nil, fmt.Errorf("missing session cookie")
	}

	sessionID := string(sessionCookie)

	// Find session and get user
	session, err := m.service.FindSession(sessionID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid or expired session: %w", err)
	}

	user, err := m.service.FindUser(session.UserID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("user not found for session: %w", err)
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

		// Route is protected - single auth method based on request type
		var userID uuid.UUID
		var err error
		
		// API clients use JWT, browsers use sessions - no fallbacks
		if hasJWTHeader(ctx) {
			userID, err = m.validateJWTAndGetUserID(ctx)
		} else {
			userID, err = m.validateSessionAndGetUserID(ctx)
		}
		
		if err != nil {
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
