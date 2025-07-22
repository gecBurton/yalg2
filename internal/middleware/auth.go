package middleware

import (
	"context"
	"fmt"
	"log"
	"strings"

	"bifrost-gov/internal/database"

	"github.com/coreos/go-oidc/v3/oidc"
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

// OIDCConfig contains OIDC provider configuration
type OIDCConfig struct {
	IssuerURL string
	ClientID  string
}

// AuthMiddleware handles JWT authentication for protected routes
type AuthMiddleware struct {
	config   *AuthConfig
	verifier *oidc.IDTokenVerifier
	db       *gorm.DB
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(config *AuthConfig, db *gorm.DB) (*AuthMiddleware, error) {
	// Auto-migrate User model
	if err := db.AutoMigrate(&database.User{}, &database.Session{}); err != nil {
		return nil, fmt.Errorf("failed to migrate user models: %w", err)
	}

	// Create OIDC provider
	ctx := context.Background()
	oidcConfig := &OIDCConfig{
		IssuerURL: "http://localhost:5556",
		ClientID:  "bifrost-client",
	}

	provider, err := oidc.NewProvider(ctx, oidcConfig.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Create ID token verifier
	verifierConfig := &oidc.Config{
		ClientID: oidcConfig.ClientID,
	}
	verifier := provider.Verifier(verifierConfig)

	return &AuthMiddleware{
		config:   config,
		verifier: verifier,
		db:       db,
	}, nil
}

// DefaultAuthConfig returns a sensible default configuration
func DefaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		ProtectedRoutes: []string{
			"/v1/*",    // All API endpoints
			"/metrics", // Metrics endpoint (user-specific)
			"/api/*",   // Internal API endpoints
		},
		PublicRoutes: []string{
			"/auth/*",   // Authentication flows
			"/",         // UI root
			"/ui/*",     // UI assets
			"/app/*",    // UI routes
			"/static/*", // Static assets
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
	idToken, err := m.verifier.Verify(tempCtx, token)
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

	// Find or create user in database
	user := &database.User{}
	err = m.db.Where("sub = ?", sub).First(user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			// User doesn't exist, create them with claims data
			email, _ := claims["email"].(string)
			name, _ := claims["name"].(string)

			user = &database.User{
				ID:    uuid.New(),
				Sub:   sub,
				Email: email,
				Name:  name,
			}

			if err := m.db.Create(user).Error; err != nil {
				return uuid.Nil, fmt.Errorf("failed to create user: %w", err)
			}

			log.Printf("Created new user: %s (%s)", user.Email, user.ID)
		} else {
			return uuid.Nil, fmt.Errorf("failed to query user: %w", err)
		}
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

	// Find session in database
	session := &database.Session{}
	err := m.db.Where("id = ? AND expires_at > NOW()", sessionID).First(session).Error
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid or expired session: %w", err)
	}

	// Get user
	user := &database.User{}
	err = m.db.Where("id = ?", session.UserID).First(user).Error
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

		// Route is protected, try JWT first, then session fallback
		userID, err := m.validateJWTAndGetUserID(ctx)
		if err != nil {
			// JWT failed, try session-based authentication
			sessionUserID, sessionErr := m.validateSessionAndGetUserID(ctx)
			if sessionErr != nil {
				log.Printf("Authentication failed for path %s: JWT=%v, Session=%v", path, err, sessionErr)
				ctx.SetStatusCode(fasthttp.StatusUnauthorized)
				ctx.SetBodyString(`{"error":"Authentication required"}`)
				ctx.SetContentType("application/json")
				return
			}
			userID = sessionUserID
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
