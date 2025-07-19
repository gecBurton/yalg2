package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
	"gorm.io/gorm"
)

// Session management is now handled through the database via AuthPlugin

// AuthHandler handles authentication routes
type AuthHandler struct {
	store    *lib.ConfigStore
	sharedDB *gorm.DB
}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler(store *lib.ConfigStore) *AuthHandler {
	return &AuthHandler{
		store:    store,
		sharedDB: nil,
	}
}

// NewAuthHandlerWithDB creates a new AuthHandler with a shared database connection
func NewAuthHandlerWithDB(store *lib.ConfigStore, db *gorm.DB) *AuthHandler {
	return &AuthHandler{
		store:    store,
		sharedDB: db,
	}
}

// RegisterRoutes registers all authentication routes
func (h *AuthHandler) RegisterRoutes(r *router.Router) {
	r.GET("/auth/login", h.oidcLoginHandler)
	r.GET("/callback", h.oidcCallbackHandler)
	r.GET("/auth/status", h.authStatusHandler)
	r.POST("/auth/logout", h.logoutHandler)
}

// generateSessionID creates a secure random session ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// oidcLoginHandler redirects to Dex for authentication
func (h *AuthHandler) oidcLoginHandler(ctx *fasthttp.RequestCtx) {
	// Build OIDC authorization URL
	params := url.Values{}
	params.Set("client_id", "bifrost-client")
	params.Set("response_type", "code")
	params.Set("redirect_uri", "http://localhost:8080/callback")
	params.Set("scope", "openid email profile")
	params.Set("state", "random-state") // In production, use a secure random state
	
	authURL := fmt.Sprintf("http://localhost:5556/auth?%s", params.Encode())
	
	ctx.Response.Header.Set("Location", authURL)
	ctx.SetStatusCode(fasthttp.StatusFound)
}

// oidcCallbackHandler handles the OIDC callback from Dex
func (h *AuthHandler) oidcCallbackHandler(ctx *fasthttp.RequestCtx) {
	// Get authorization code from query params
	code := string(ctx.QueryArgs().Peek("code"))
	if code == "" {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString("Missing authorization code")
		return
	}

	// Exchange code for tokens
	tokenURL := "http://localhost:5556/token"
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", "bifrost-client")
	data.Set("client_secret", "bifrost-secret")
	data.Set("code", code)
	data.Set("redirect_uri", "http://localhost:8080/callback")

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

	// Verify and parse the ID token using our OIDC verifier
	// Create OIDC config for token verification
	oidcConfig := &OIDCConfig{
		IssuerURL: "http://localhost:5556",
		ClientID:  "bifrost-client",
	}
	
	// Use shared database if available, otherwise no database
	var authPlugin *AuthPlugin
	if h.sharedDB != nil {
		authPlugin, err = NewAuthPluginWithDB(oidcConfig, h.sharedDB)
	} else {
		// Fallback to database URL if no shared DB
		oidcConfig.DatabaseURL = os.Getenv("DATABASE_URL")
		authPlugin, err = NewAuthPlugin(oidcConfig)
	}
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString("Failed to initialize OIDC verifier")
		return
	}
	
	// Verify the ID token
	tokenCtx := context.Background()
	idToken, err := authPlugin.GetVerifier().Verify(tokenCtx, tokenResp.IDToken)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString("Failed to verify ID token")
		return
	}
	
	// Extract claims from the verified token
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString("Failed to extract token claims")
		return
	}
	
	// Create user from token claims and store in database
	user := &User{}
	if sub, ok := claims["sub"].(string); ok {
		user.Sub = sub
	}
	if email, ok := claims["email"].(string); ok {
		user.Email = email
	}
	if name, ok := claims["name"].(string); ok {
		user.Name = name
	} else if preferredUsername, ok := claims["preferred_username"].(string); ok {
		user.Name = preferredUsername
	}
	
	// Store user in database
	if authPlugin.GetDB() != nil {
		if err := authPlugin.InsertOrUpdateUser(user); err != nil {
			log.Printf("Warning: failed to store user in database: %v", err)
		}
	}
	
	// Create session
	sessionID, err := generateSessionID()
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString("Failed to generate session")
		return
	}

	// Create session with real user data and ID token
	session := &Session{
		ID:        sessionID,
		UserID:    user.ID,
		User:      user,
		IDToken:   tokenResp.IDToken, // Store the actual JWT ID token
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	// Save session to database
	if err := authPlugin.CreateSession(session); err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString("Failed to create session")
		log.Fatalf("Critical error: failed to store session in database: %v", err)
		return
	}
	
	log.Printf("Successfully created session: ID=%s, UserID=%d, ExpiresAt=%v", session.ID, session.UserID, session.ExpiresAt)

	// Set session cookie
	cookie := fmt.Sprintf("session=%s; HttpOnly; Path=/; Max-Age=86400", sessionID)
	ctx.Response.Header.Set("Set-Cookie", cookie)

	// Redirect to frontend
	ctx.Response.Header.Set("Location", "/")
	ctx.SetStatusCode(fasthttp.StatusFound)
}

// authStatusHandler returns the current authentication status
func (h *AuthHandler) authStatusHandler(ctx *fasthttp.RequestCtx) {
	// Get session from cookie
	sessionID := string(ctx.Request.Header.Cookie("session"))
	if sessionID == "" {
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.SetBodyString(`{"authenticated": false}`)
		return
	}

	// Get session from database
	var session *Session
	var err error
	
	if h.sharedDB != nil {
		// Create temporary auth plugin to access session methods
		oidcConfig := &OIDCConfig{
			IssuerURL: "http://localhost:5556",
			ClientID:  "bifrost-client",
		}
		authPlugin, pluginErr := NewAuthPluginWithDB(oidcConfig, h.sharedDB)
		if pluginErr != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString(`{"authenticated": false}`)
			log.Fatalf("Critical error: failed to create auth plugin for session lookup: %v", pluginErr)
			return
		}
		
		session, err = authPlugin.GetSession(sessionID)
	} else {
		// No database available - this should never happen in production
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"authenticated": false}`)
		log.Fatalf("Critical error: no database connection available for session management")
		return
	}
	
	if err != nil || session == nil {
		// Session not found or expired
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.SetBodyString(`{"authenticated": false}`)
		return
	}

	// Return authenticated status with ID token
	ctx.SetContentType("application/json")
	response := map[string]any{
		"authenticated": true,
		"user_id":      session.UserID,
		"id_token":     session.IDToken,
		"user":         session.User,
	}

	jsonResp, _ := json.Marshal(response)
	ctx.SetBody(jsonResp)
}

// logoutHandler clears the session
func (h *AuthHandler) logoutHandler(ctx *fasthttp.RequestCtx) {
	sessionID := string(ctx.Request.Header.Cookie("session"))
	if sessionID != "" {
		if h.sharedDB == nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString(`{"success": false}`)
			log.Fatalf("Critical error: no database connection available for session deletion")
			return
		}

		// Delete session from database
		oidcConfig := &OIDCConfig{
			IssuerURL: "http://localhost:5556",
			ClientID:  "bifrost-client",
		}
		authPlugin, err := NewAuthPluginWithDB(oidcConfig, h.sharedDB)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString(`{"success": false}`)
			log.Fatalf("Critical error: failed to create auth plugin for session deletion: %v", err)
			return
		}

		if err := authPlugin.DeleteSession(sessionID); err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString(`{"success": false}`)
			log.Fatalf("Critical error: failed to delete session from database: %v", err)
			return
		}
	}

	// Clear cookie
	ctx.Response.Header.Set("Set-Cookie", "session=; HttpOnly; Path=/; Max-Age=0")
	ctx.SetContentType("application/json")
	ctx.SetBodyString(`{"success": true}`)
}