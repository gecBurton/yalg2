package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"bifrost-gov/internal/database"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

// AuthConfig defines which routes require authentication
type AuthConfig struct {
	// Routes that require authentication (supports wildcards)
	ProtectedRoutes []string
	// Routes that are always public (supports wildcards)
	PublicRoutes []string
	// Pre-computed exact route lookups for performance
	ExactPublic    map[string]bool
	ExactProtected map[string]bool
}

// WebAuthHandler handles web-based authentication routes (login/logout/callback)
type WebAuthHandler struct {
	store   *lib.ConfigStore
	service *AuthService
}

// AuthMiddleware handles JWT authentication for protected routes
type AuthMiddleware struct {
	config  *AuthConfig
	service *AuthService
}

// NewWebAuthHandler creates a new web authentication handler
func NewWebAuthHandler(store *lib.ConfigStore, service *AuthService) *WebAuthHandler {
	return &WebAuthHandler{
		store:   store,
		service: service,
	}
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(config *AuthConfig, service *AuthService) *AuthMiddleware {
	return &AuthMiddleware{
		config:  config,
		service: service,
	}
}

// DefaultAuthConfig returns a sensible default configuration
func DefaultAuthConfig() *AuthConfig {
	config := &AuthConfig{
		ProtectedRoutes: []string{
			"/v1/*",      // All API endpoints
			"/metrics",   // Metrics endpoint (user-specific)
			"/api/*",     // Internal API endpoints
			"/admin/*",   // Admin pages and endpoints
		},
		PublicRoutes: []string{
			"/auth/*",   // Authentication flows
			"/",         // UI root
			"/ui/*",     // UI assets
			"/app/*",    // UI routes
			"/static/*", // Static assets
		},
		ExactPublic:    make(map[string]bool),
		ExactProtected: make(map[string]bool),
	}
	
	// Pre-compute exact matches for performance
	config.ExactPublic["/"] = true
	config.ExactPublic["/auth/login"] = true
	config.ExactPublic["/auth/logout"] = true
	config.ExactPublic["/auth/status"] = true
	config.ExactPublic["/callback"] = true
	
	config.ExactProtected["/metrics"] = true
	
	return config
}

// generateSessionID creates a secure random session ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
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

// RegisterRoutes registers all web authentication routes
func (h *WebAuthHandler) RegisterRoutes(r *router.Router) {
	r.GET("/auth/login", h.loginHandler)
	r.GET("/callback", h.callbackHandler)
	r.GET("/auth/status", h.statusHandler)
	r.POST("/auth/logout", h.logoutHandler)
}

// loginHandler redirects to OIDC provider for authentication
func (h *WebAuthHandler) loginHandler(ctx *fasthttp.RequestCtx) {
	config := h.service.GetConfig()
	
	// Build OIDC authorization URL
	params := url.Values{}
	params.Set("client_id", config.ClientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", config.RedirectURI)
	params.Set("scope", "openid email profile")
	params.Set("state", "random-state") // TODO: Use secure random state in production

	authURL := fmt.Sprintf("%s/auth?%s", config.IssuerURL, params.Encode())

	ctx.Response.Header.Set("Location", authURL)
	ctx.SetStatusCode(fasthttp.StatusFound)
}

// callbackHandler handles the OIDC callback
func (h *WebAuthHandler) callbackHandler(ctx *fasthttp.RequestCtx) {
	// Get authorization code from query params
	code := string(ctx.QueryArgs().Peek("code"))
	if code == "" {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString("Missing authorization code")
		return
	}

	config := h.service.GetConfig()

	// Exchange code for tokens
	tokenURL := fmt.Sprintf("%s/token", config.IssuerURL)
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", config.ClientID)
	data.Set("client_secret", config.ClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", config.RedirectURI)

	// Make token request
	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString("Failed to exchange code for token")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString("Token exchange failed")
		return
	}

	// Parse token response
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString("Failed to parse token response")
		return
	}

	// Verify the ID token and get claims
	claims, err := h.service.VerifyIDToken(tokenResp.IDToken)
	if err != nil {
		log.Printf("Failed to verify ID token: %v", err)
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.SetBodyString("Invalid ID token")
		return
	}

	// Get user subject
	sub, ok := claims["sub"].(string)
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString("Invalid token subject")
		return
	}

	// Find or create user
	user, err := h.service.FindOrCreateUser(sub, claims)
	if err != nil {
		log.Printf("Failed to find/create user: %v", err)
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString("Failed to process user")
		return
	}

	log.Printf("Created new user via web login: %s (%s)", user.Email, user.ID)

	// Create session
	sessionID, err := generateSessionID()
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString("Failed to generate session ID")
		return
	}

	session := &database.Session{
		ID:        sessionID,
		UserID:    user.ID,
		IDToken:   tokenResp.IDToken,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hour session
	}

	if err := h.service.CreateSession(session); err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString("Failed to create session")
		return
	}

	// Set session cookie
	cookie := &fasthttp.Cookie{}
	cookie.SetKey("session")
	cookie.SetValue(sessionID)
	cookie.SetHTTPOnly(true)
	cookie.SetSecure(false)        // Set to true in production with HTTPS
	cookie.SetMaxAge(24 * 60 * 60) // 24 hours
	cookie.SetPath("/")
	ctx.Response.Header.SetCookie(cookie)

	// Redirect to home
	ctx.Response.Header.Set("Location", "/")
	ctx.SetStatusCode(fasthttp.StatusFound)
}

// statusHandler returns the authentication status
func (h *WebAuthHandler) statusHandler(ctx *fasthttp.RequestCtx) {
	sessionID := string(ctx.Request.Header.Cookie("session"))
	if sessionID == "" {
		ctx.SetContentType("application/json")
		ctx.SetBody([]byte(`{"authenticated": false}`))
		return
	}

	// Look up session
	session, err := h.service.FindSessionWithUser(sessionID)
	if err != nil {
		ctx.SetContentType("application/json")
		ctx.SetBody([]byte(`{"authenticated": false}`))
		return
	}

	// Return user info and token
	response := map[string]any{
		"authenticated": true,
		"user_id":       session.User.ID,
		"email":         session.User.Email,
		"name":          session.User.Name,
		"is_admin":      session.User.IsAdmin,
		"id_token":      session.IDToken,
	}

	responseJSON, _ := json.Marshal(response)
	ctx.SetContentType("application/json")
	ctx.SetBody(responseJSON)
}

// logoutHandler handles logout
func (h *WebAuthHandler) logoutHandler(ctx *fasthttp.RequestCtx) {
	sessionID := string(ctx.Request.Header.Cookie("session"))
	if sessionID != "" {
		// Delete session from database
		h.service.DeleteSession(sessionID)
	}

	// Clear session cookie
	cookie := &fasthttp.Cookie{}
	cookie.SetKey("session")
	cookie.SetValue("")
	cookie.SetMaxAge(-1) // Delete cookie
	cookie.SetPath("/")
	ctx.Response.Header.SetCookie(cookie)

	ctx.SetContentType("application/json")
	ctx.SetBody([]byte(`{"success": true}`))
}
