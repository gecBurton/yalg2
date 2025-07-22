package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"bifrost-gov/internal/models"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
	"gorm.io/gorm"
)

// WebAuthHandler handles web-based authentication routes (login/logout/callback)
type WebAuthHandler struct {
	store    *lib.ConfigStore
	db       *gorm.DB
	verifier *oidc.IDTokenVerifier
}

// NewWebAuthHandler creates a new web authentication handler
func NewWebAuthHandler(store *lib.ConfigStore, db *gorm.DB) (*WebAuthHandler, error) {
	// Auto-migrate models
	if err := db.AutoMigrate(&models.User{}, &models.Session{}); err != nil {
		return nil, fmt.Errorf("failed to migrate auth models: %w", err)
	}

	// Create OIDC provider
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, "http://localhost:5556")
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Create ID token verifier
	verifierConfig := &oidc.Config{
		ClientID: "bifrost-client",
	}
	verifier := provider.Verifier(verifierConfig)

	return &WebAuthHandler{
		store:    store,
		db:       db,
		verifier: verifier,
	}, nil
}

// RegisterRoutes registers all web authentication routes
func (h *WebAuthHandler) RegisterRoutes(r *router.Router) {
	r.GET("/auth/login", h.loginHandler)
	r.GET("/callback", h.callbackHandler)
	r.GET("/auth/status", h.statusHandler)
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

// loginHandler redirects to OIDC provider for authentication
func (h *WebAuthHandler) loginHandler(ctx *fasthttp.RequestCtx) {
	// Build OIDC authorization URL
	params := url.Values{}
	params.Set("client_id", "bifrost-client")
	params.Set("response_type", "code")
	params.Set("redirect_uri", "http://localhost:8080/callback")
	params.Set("scope", "openid email profile")
	params.Set("state", "random-state") // TODO: Use secure random state in production

	authURL := fmt.Sprintf("http://localhost:5556/auth?%s", params.Encode())

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

	// Verify the ID token
	tokenCtx := context.Background()
	idToken, err := h.verifier.Verify(tokenCtx, tokenResp.IDToken)
	if err != nil {
		log.Printf("Failed to verify ID token: %v", err)
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.SetBodyString("Invalid ID token")
		return
	}

	// Extract claims
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString("Failed to parse token claims")
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
	user := &models.User{}
	err = h.db.Where("sub = ?", sub).First(user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			// Create new user
			email, _ := claims["email"].(string)
			name, _ := claims["name"].(string)

			user = &models.User{
				ID:    uuid.New(),
				Sub:   sub,
				Email: email,
				Name:  name,
			}

			if err := h.db.Create(user).Error; err != nil {
				ctx.SetStatusCode(fasthttp.StatusInternalServerError)
				ctx.SetBodyString("Failed to create user")
				return
			}

			log.Printf("Created new user via web login: %s (%s)", user.Email, user.ID)
		} else {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString("Database error")
			return
		}
	}

	// Create session
	sessionID, err := generateSessionID()
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString("Failed to generate session ID")
		return
	}

	session := &models.Session{
		ID:        sessionID,
		UserID:    user.ID,
		IDToken:   tokenResp.IDToken,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hour session
	}

	if err := h.db.Create(session).Error; err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString("Failed to create session")
		return
	}

	// Set session cookie
	cookie := &fasthttp.Cookie{}
	cookie.SetKey("session")
	cookie.SetValue(sessionID)
	cookie.SetHTTPOnly(true)
	cookie.SetSecure(false) // Set to true in production with HTTPS
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
	session := &models.Session{}
	err := h.db.Preload("User").Where("id = ? AND expires_at > ?", sessionID, time.Now()).First(session).Error
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
		h.db.Where("id = ?", sessionID).Delete(&models.Session{})
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