package middleware

import (
	"strings"
	"testing"
	"time"

	"bifrost-gov/internal/database"
	"bifrost-gov/internal/testutil"

	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
	"gorm.io/gorm"
)

// setupTestMiddleware creates a test auth middleware using existing test database
func setupTestMiddleware(t *testing.T) (*AuthMiddleware, *gorm.DB) {
	db := testutil.SetupTestDB(t, &database.User{}, &database.Session{})

	service, err := NewAuthService(db)
	if err != nil {
		t.Fatalf("Failed to create auth service: %v", err)
	}

	config := &AuthConfig{
		ProtectedRoutes: []string{"/v1/*", "/api/*", "/protected"},
		PublicRoutes:    []string{"/auth/*", "/public/*", "/"},
	}

	middleware := NewAuthMiddleware(config, service)
	return middleware, db
}

// createTestUserForMiddleware creates a test user in the database for middleware tests
func createTestUserForMiddleware(t *testing.T, db *gorm.DB) *database.User {
	user := &database.User{
		ID:    uuid.New(),
		Sub:   "test-subject-123",
		Email: "test@example.com",
		Name:  "Test User",
	}

	err := db.Create(user).Error
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	return user
}

func TestAuthMiddleware_needsAuthentication(t *testing.T) {
	middleware, _ := setupTestMiddleware(t)

	tests := []struct {
		path     string
		expected bool
		desc     string
	}{
		{"/", false, "root path should be public"},
		{"/auth/login", false, "auth routes should be public"},
		{"/auth/callback", false, "auth callback should be public"},
		{"/public/health", false, "public routes should be public"},
		{"/v1/completions", true, "v1 API routes should be protected"},
		{"/api/users", true, "internal API routes should be protected"},
		{"/protected", true, "explicitly protected routes should require auth"},
		{"/unknown", false, "unknown routes should default to public"},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			result := middleware.needsAuthentication(test.path)
			if result != test.expected {
				t.Errorf("Path %s: expected %v, got %v", test.path, test.expected, result)
			}
		})
	}
}

func TestAuthMiddleware_validateJWTAndGetUserID_MissingHeader(t *testing.T) {
	middleware, _ := setupTestMiddleware(t)

	ctx := &fasthttp.RequestCtx{}
	// No Authorization header set

	_, err := middleware.validateJWTAndGetUserID(ctx)
	if err == nil {
		t.Error("Expected error for missing Authorization header")
	}

	if !strings.Contains(err.Error(), "missing Authorization header") {
		t.Errorf("Expected 'missing Authorization header' error, got: %v", err)
	}
}

func TestAuthMiddleware_validateJWTAndGetUserID_InvalidFormat(t *testing.T) {
	middleware, _ := setupTestMiddleware(t)

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("Authorization", "InvalidFormat token123")

	_, err := middleware.validateJWTAndGetUserID(ctx)
	if err == nil {
		t.Error("Expected error for invalid Authorization header format")
	}

	if !strings.Contains(err.Error(), "invalid Authorization header format") {
		t.Errorf("Expected 'invalid Authorization header format' error, got: %v", err)
	}
}

func TestAuthMiddleware_validateSessionAndGetUserID_MissingCookie(t *testing.T) {
	middleware, _ := setupTestMiddleware(t)

	ctx := &fasthttp.RequestCtx{}
	// No session cookie set

	_, err := middleware.validateSessionAndGetUserID(ctx)
	if err == nil {
		t.Error("Expected error for missing session cookie")
	}

	if !strings.Contains(err.Error(), "missing session cookie") {
		t.Errorf("Expected 'missing session cookie' error, got: %v", err)
	}
}

func TestAuthMiddleware_validateSessionAndGetUserID_InvalidSession(t *testing.T) {
	middleware, _ := setupTestMiddleware(t)

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetCookie("session", "invalid-session-id")

	_, err := middleware.validateSessionAndGetUserID(ctx)
	if err == nil {
		t.Error("Expected error for invalid session")
	}

	if !strings.Contains(err.Error(), "invalid or expired session") {
		t.Errorf("Expected 'invalid or expired session' error, got: %v", err)
	}
}

func TestAuthMiddleware_Handler_PublicRoute(t *testing.T) {
	middleware, _ := setupTestMiddleware(t)

	handlerCalled := false
	nextHandler := func(ctx *fasthttp.RequestCtx) {
		handlerCalled = true
		ctx.SetStatusCode(fasthttp.StatusOK)
	}

	handler := middleware.Handler(nextHandler)

	ctx := &fasthttp.RequestCtx{}
	ctx.URI().SetPath("/public/test")

	handler(ctx)

	if !handlerCalled {
		t.Error("Next handler should have been called for public route")
	}

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Errorf("Expected status 200, got %d", ctx.Response.StatusCode())
	}
}

func TestAuthMiddleware_Handler_ProtectedRoute_NoAuth(t *testing.T) {
	middleware, _ := setupTestMiddleware(t)

	handlerCalled := false
	nextHandler := func(ctx *fasthttp.RequestCtx) {
		handlerCalled = true
	}

	handler := middleware.Handler(nextHandler)

	ctx := &fasthttp.RequestCtx{}
	ctx.URI().SetPath("/v1/completions")
	// No authentication provided

	handler(ctx)

	if handlerCalled {
		t.Error("Next handler should not have been called without authentication")
	}

	if ctx.Response.StatusCode() != fasthttp.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", ctx.Response.StatusCode())
	}

	body := string(ctx.Response.Body())
	if !strings.Contains(body, "Authentication required") {
		t.Errorf("Expected 'Authentication required' in response body, got: %s", body)
	}
}

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		path     string
		pattern  string
		expected bool
		desc     string
	}{
		{"/exact", "/exact", true, "exact match should work"},
		{"/different", "/exact", false, "different paths should not match"},
		{"/api/users", "/api/*", true, "wildcard should match subdirectories"},
		{"/api/users/123", "/api/*", true, "wildcard should match deep subdirectories"},
		{"/other/users", "/api/*", false, "wildcard should not match different prefixes"},
		{"/auth", "/auth/*", false, "wildcard should not match exact prefix without slash"},
		{"/auth/", "/auth/*", true, "wildcard should match prefix with slash"},
		{"/auth/login", "/auth/*", true, "wildcard should match prefix with path"},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			result := matchesPattern(test.path, test.pattern)
			if result != test.expected {
				t.Errorf("matchesPattern(%s, %s): expected %v, got %v", test.path, test.pattern, test.expected, result)
			}
		})
	}
}

func TestAuthMiddleware_Handler_UserContext(t *testing.T) {
	middleware, db := setupTestMiddleware(t)
	user := createTestUserForMiddleware(t, db)

	// Create a valid session
	session := &database.Session{
		ID:        "valid-session-123",
		UserID:    user.ID,
		IDToken:   "test-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	err := db.Create(session).Error
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	handlerCalled := false
	var capturedUserID uuid.UUID
	var capturedAuth bool

	nextHandler := func(ctx *fasthttp.RequestCtx) {
		handlerCalled = true
		capturedUserID = ctx.UserValue("user_id").(uuid.UUID)
		capturedAuth = ctx.UserValue("authenticated").(bool)
		ctx.SetStatusCode(fasthttp.StatusOK)
	}

	handler := middleware.Handler(nextHandler)

	ctx := &fasthttp.RequestCtx{}
	ctx.URI().SetPath("/v1/completions")
	ctx.Request.Header.SetCookie("session", "valid-session-123")

	handler(ctx)

	if !handlerCalled {
		t.Error("Next handler should have been called with valid session")
	}

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Errorf("Expected status 200, got %d", ctx.Response.StatusCode())
	}

	if capturedUserID != user.ID {
		t.Errorf("Expected user ID %s, got %s", user.ID, capturedUserID)
	}

	if !capturedAuth {
		t.Error("Expected authenticated to be true")
	}
}

func TestDefaultAuthConfig(t *testing.T) {
	config := DefaultAuthConfig()

	if config == nil {
		t.Fatal("DefaultAuthConfig returned nil")
	}

	// Check protected routes
	expectedProtected := []string{"/v1/*", "/metrics", "/api/*"}
	if len(config.ProtectedRoutes) != len(expectedProtected) {
		t.Errorf("Expected %d protected routes, got %d", len(expectedProtected), len(config.ProtectedRoutes))
	}

	for i, expected := range expectedProtected {
		if i >= len(config.ProtectedRoutes) || config.ProtectedRoutes[i] != expected {
			t.Errorf("Expected protected route %s at index %d, got %s", expected, i, config.ProtectedRoutes[i])
		}
	}

	// Check public routes
	expectedPublic := []string{"/auth/*", "/", "/ui/*", "/app/*", "/static/*"}
	if len(config.PublicRoutes) != len(expectedPublic) {
		t.Errorf("Expected %d public routes, got %d", len(expectedPublic), len(config.PublicRoutes))
	}

	for i, expected := range expectedPublic {
		if i >= len(config.PublicRoutes) || config.PublicRoutes[i] != expected {
			t.Errorf("Expected public route %s at index %d, got %s", expected, i, config.PublicRoutes[i])
		}
	}
	
	// Check pre-computed exact routes for performance
	if config.ExactPublic == nil {
		t.Error("ExactPublic map should be initialized")
	}
	if config.ExactProtected == nil {
		t.Error("ExactProtected map should be initialized")
	}
	
	// Verify some pre-computed routes
	if !config.ExactPublic["/"] {
		t.Error("Root route should be in ExactPublic")
	}
	if !config.ExactPublic["/auth/login"] {
		t.Error("Login route should be in ExactPublic")
	}
	if !config.ExactProtected["/metrics"] {
		t.Error("Metrics route should be in ExactProtected")
	}
}
