package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"bifrost-gov/internal/database"
	"bifrost-gov/internal/testutil"

	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
	"gorm.io/gorm"
)

// setupWebAuthTest creates a web auth handler for testing
func setupWebAuthTest(t *testing.T) (*WebAuthHandler, *gorm.DB) {
	db := testutil.SetupTestDB(t, &database.User{}, &database.Session{})
	
	// Create mock config store
	store := &lib.ConfigStore{}
	
	// Create auth service
	service, err := NewAuthService(db)
	if err != nil {
		t.Fatalf("Failed to create auth service: %v", err)
	}
	
	handler := NewWebAuthHandler(store, service)
	return handler, db
}

func TestNewWebAuthHandler(t *testing.T) {
	handler, _ := setupWebAuthTest(t)
	
	if handler == nil {
		t.Fatal("WebAuthHandler should not be nil")
	}
	
	if handler.store == nil {
		t.Error("Store should not be nil")
	}
	
	if handler.service == nil {
		t.Error("Service should not be nil")
	}
}

func TestGenerateSessionID(t *testing.T) {
	sessionID1, err1 := generateSessionID()
	if err1 != nil {
		t.Fatalf("Failed to generate session ID: %v", err1)
	}
	
	sessionID2, err2 := generateSessionID()
	if err2 != nil {
		t.Fatalf("Failed to generate second session ID: %v", err2)
	}
	
	if sessionID1 == sessionID2 {
		t.Error("Session IDs should be unique")
	}
	
	if len(sessionID1) == 0 {
		t.Error("Session ID should not be empty")
	}
	
	// Should be base64 URL encoded (no padding issues)
	if strings.Contains(sessionID1, "+") || strings.Contains(sessionID1, "/") {
		t.Error("Session ID should use URL-safe base64 encoding")
	}
}

func TestRegisterRoutes(t *testing.T) {
	handler, _ := setupWebAuthTest(t)
	
	r := router.New()
	handler.RegisterRoutes(r)
	
	// Test that routes are registered by making requests
	tests := []struct {
		method string
		path   string
	}{
		{"GET", "/auth/login"},
		{"GET", "/callback"},
		{"GET", "/auth/status"},
		{"POST", "/auth/logout"},
	}
	
	for _, test := range tests {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			ctx := &fasthttp.RequestCtx{}
			ctx.Request.SetRequestURI(test.path)
			ctx.Request.Header.SetMethod(test.method)
			
			// Should not panic when calling registered routes
			r.Handler(ctx)
			
			// Should not return 404 (route exists)
			if ctx.Response.StatusCode() == fasthttp.StatusNotFound {
				t.Errorf("Route %s %s should be registered", test.method, test.path)
			}
		})
	}
}

func TestLoginHandler(t *testing.T) {
	handler, _ := setupWebAuthTest(t)
	
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/auth/login")
	ctx.Request.Header.SetMethod("GET")
	
	handler.loginHandler(ctx)
	
	// Should redirect to OIDC provider
	if ctx.Response.StatusCode() != fasthttp.StatusFound {
		t.Errorf("Expected status %d, got %d", fasthttp.StatusFound, ctx.Response.StatusCode())
	}
	
	location := string(ctx.Response.Header.Peek("Location"))
	if location == "" {
		t.Error("Location header should be set for redirect")
	}
	
	// Should redirect to OIDC provider
	if !strings.Contains(location, "http://localhost:5556/auth") {
		t.Errorf("Should redirect to OIDC provider, got: %s", location)
	}
	
	// Should contain required OIDC parameters
	parsedURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Failed to parse redirect URL: %v", err)
	}
	
	queryParams := parsedURL.Query()
	requiredParams := []string{"client_id", "response_type", "redirect_uri", "scope", "state"}
	
	for _, param := range requiredParams {
		if queryParams.Get(param) == "" {
			t.Errorf("Missing required OIDC parameter: %s", param)
		}
	}
	
	// Verify specific parameter values
	if queryParams.Get("client_id") != "bifrost-client" {
		t.Errorf("Expected client_id 'bifrost-client', got '%s'", queryParams.Get("client_id"))
	}
	
	if queryParams.Get("response_type") != "code" {
		t.Errorf("Expected response_type 'code', got '%s'", queryParams.Get("response_type"))
	}
	
	if queryParams.Get("scope") != "openid email profile" {
		t.Errorf("Expected scope 'openid email profile', got '%s'", queryParams.Get("scope"))
	}
}

func TestCallbackHandler_MissingCode(t *testing.T) {
	handler, _ := setupWebAuthTest(t)
	
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/callback")
	ctx.Request.Header.SetMethod("GET")
	// No 'code' query parameter
	
	handler.callbackHandler(ctx)
	
	if ctx.Response.StatusCode() != fasthttp.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	}
	
	body := string(ctx.Response.Body())
	if !strings.Contains(body, "Missing authorization code") {
		t.Errorf("Expected error message about missing code, got: %s", body)
	}
}

func TestCallbackHandler_InvalidCode(t *testing.T) {
	handler, _ := setupWebAuthTest(t)
	
	// Create a mock OIDC server that returns error
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "invalid_grant"}`))
	}))
	defer mockServer.Close()
	
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/callback?code=invalid_code")
	ctx.Request.Header.SetMethod("GET")
	
	// Note: This test will fail at token exchange since we're not mocking the full OIDC flow
	// But we can test that it attempts to process the code
	handler.callbackHandler(ctx)
	
	// Should fail at token exchange step
	if ctx.Response.StatusCode() == fasthttp.StatusOK {
		t.Error("Should not succeed with invalid code")
	}
}

func TestStatusHandler_NoSession(t *testing.T) {
	handler, _ := setupWebAuthTest(t)
	
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/auth/status")
	ctx.Request.Header.SetMethod("GET")
	// No session cookie
	
	handler.statusHandler(ctx)
	
	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Errorf("Expected status %d, got %d", fasthttp.StatusOK, ctx.Response.StatusCode())
	}
	
	body := string(ctx.Response.Body())
	var response map[string]interface{}
	err := json.Unmarshal([]byte(body), &response)
	if err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}
	
	authenticated, ok := response["authenticated"].(bool)
	if !ok {
		t.Error("Response should contain 'authenticated' boolean field")
	}
	
	if authenticated {
		t.Error("Should not be authenticated without session")
	}
	
	contentType := string(ctx.Response.Header.Peek("Content-Type"))
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}
}

func TestStatusHandler_ValidSession(t *testing.T) {
	handler, db := setupWebAuthTest(t)
	
	// Create test user and session
	user := &database.User{
		ID:    uuid.New(),
		Sub:   "test-subject",
		Email: "test@example.com",
		Name:  "Test User",
	}
	db.Create(user)
	
	session := &database.Session{
		ID:        "test-session-id",
		UserID:    user.ID,
		IDToken:   "test-id-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	db.Create(session)
	
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/auth/status")
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.Header.SetCookie("session", "test-session-id")
	
	handler.statusHandler(ctx)
	
	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Errorf("Expected status %d, got %d", fasthttp.StatusOK, ctx.Response.StatusCode())
	}
	
	body := string(ctx.Response.Body())
	var response map[string]interface{}
	err := json.Unmarshal([]byte(body), &response)
	if err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}
	
	authenticated, ok := response["authenticated"].(bool)
	if !ok || !authenticated {
		t.Error("Should be authenticated with valid session")
	}
	
	// Check user data in response
	if response["email"] != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%v'", response["email"])
	}
	
	if response["name"] != "Test User" {
		t.Errorf("Expected name 'Test User', got '%v'", response["name"])
	}
	
	if response["id_token"] != "test-id-token" {
		t.Errorf("Expected id_token 'test-id-token', got '%v'", response["id_token"])
	}
}

func TestStatusHandler_ExpiredSession(t *testing.T) {
	handler, db := setupWebAuthTest(t)
	
	// Create test user and expired session
	user := &database.User{
		ID:    uuid.New(),
		Sub:   "test-subject",
		Email: "test@example.com",
		Name:  "Test User",
	}
	db.Create(user)
	
	expiredSession := &database.Session{
		ID:        "expired-session-id",
		UserID:    user.ID,
		IDToken:   "test-id-token",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}
	db.Create(expiredSession)
	
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/auth/status")
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.Header.SetCookie("session", "expired-session-id")
	
	handler.statusHandler(ctx)
	
	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Errorf("Expected status %d, got %d", fasthttp.StatusOK, ctx.Response.StatusCode())
	}
	
	body := string(ctx.Response.Body())
	var response map[string]interface{}
	err := json.Unmarshal([]byte(body), &response)
	if err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}
	
	authenticated, ok := response["authenticated"].(bool)
	if !ok {
		t.Error("Response should contain 'authenticated' boolean field")
	}
	
	if authenticated {
		t.Error("Should not be authenticated with expired session")
	}
}

func TestLogoutHandler_NoSession(t *testing.T) {
	handler, _ := setupWebAuthTest(t)
	
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/auth/logout")
	ctx.Request.Header.SetMethod("POST")
	// No session cookie
	
	handler.logoutHandler(ctx)
	
	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Errorf("Expected status %d, got %d", fasthttp.StatusOK, ctx.Response.StatusCode())
	}
	
	body := string(ctx.Response.Body())
	var response map[string]interface{}
	err := json.Unmarshal([]byte(body), &response)
	if err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}
	
	success, ok := response["success"].(bool)
	if !ok || !success {
		t.Error("Should return success even without session")
	}
	
	// Should clear cookie anyway
	cookies := ctx.Response.Header.PeekCookie("session")
	if len(cookies) == 0 {
		t.Error("Should set session cookie to clear it")
	}
}

func TestLogoutHandler_ValidSession(t *testing.T) {
	handler, db := setupWebAuthTest(t)
	
	// Create test user and session
	user := &database.User{
		ID:    uuid.New(),
		Sub:   "test-subject",
		Email: "test@example.com",
		Name:  "Test User",
	}
	db.Create(user)
	
	session := &database.Session{
		ID:        "logout-test-session",
		UserID:    user.ID,
		IDToken:   "test-id-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	db.Create(session)
	
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/auth/logout")
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.Header.SetCookie("session", "logout-test-session")
	
	handler.logoutHandler(ctx)
	
	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Errorf("Expected status %d, got %d", fasthttp.StatusOK, ctx.Response.StatusCode())
	}
	
	body := string(ctx.Response.Body())
	var response map[string]interface{}
	err := json.Unmarshal([]byte(body), &response)
	if err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}
	
	success, ok := response["success"].(bool)
	if !ok || !success {
		t.Error("Should return success for valid logout")
	}
	
	// Verify session was deleted from database
	var count int64
	db.Model(&database.Session{}).Where("id = ?", "logout-test-session").Count(&count)
	if count != 0 {
		t.Errorf("Session should be deleted from database, found %d sessions", count)
	}
	
	// Should clear cookie
	cookies := ctx.Response.Header.PeekCookie("session")
	if len(cookies) == 0 {
		t.Error("Should set session cookie to clear it")
	}
}
