package middleware

import (
	"testing"
	"time"

	"bifrost-gov/internal/database"
	"bifrost-gov/internal/testutil"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// setupTestDB uses the existing test database setup from other middleware tests
func setupTestDB(t *testing.T) *gorm.DB {
	return testutil.SetupTestDB(t, &database.User{}, &database.Session{})
}

func TestNewAuthService(t *testing.T) {
	db := setupTestDB(t)

	service, err := NewAuthService(db)
	if err != nil {
		t.Fatalf("Failed to create auth service: %v", err)
	}

	if service == nil {
		t.Fatal("Auth service is nil")
	}

	if service.db != db {
		t.Error("Database not properly set")
	}

	if service.verifier == nil {
		t.Error("OIDC verifier not initialized")
	}

	if service.config == nil {
		t.Error("OIDC config not initialized")
	}

	// Test config values
	if service.config.IssuerURL != "http://localhost:5556" {
		t.Errorf("Expected IssuerURL 'http://localhost:5556', got '%s'", service.config.IssuerURL)
	}

	if service.config.ClientID != "bifrost-client" {
		t.Errorf("Expected ClientID 'bifrost-client', got '%s'", service.config.ClientID)
	}
}

func TestFindOrCreateUser_CreateNew(t *testing.T) {
	db := setupTestDB(t)
	service, err := NewAuthService(db)
	if err != nil {
		t.Fatalf("Failed to create auth service: %v", err)
	}

	claims := map[string]any{
		"sub":   "test-subject-123",
		"email": "test@example.com",
		"name":  "Test User",
	}

	user, err := service.FindOrCreateUser("test-subject-123", claims)
	if err != nil {
		t.Fatalf("Failed to find/create user: %v", err)
	}

	if user == nil {
		t.Fatal("User is nil")
	}

	if user.Sub != "test-subject-123" {
		t.Errorf("Expected sub 'test-subject-123', got '%s'", user.Sub)
	}

	if user.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", user.Email)
	}

	if user.Name != "Test User" {
		t.Errorf("Expected name 'Test User', got '%s'", user.Name)
	}

	if user.ID == uuid.Nil {
		t.Error("User ID should not be nil")
	}

	// Verify user was saved to database
	var count int64
	db.Model(&database.User{}).Where("sub = ?", "test-subject-123").Count(&count)
	if count != 1 {
		t.Errorf("Expected 1 user in database, got %d", count)
	}
}

func TestFindOrCreateUser_FindExisting(t *testing.T) {
	db := setupTestDB(t)
	service, err := NewAuthService(db)
	if err != nil {
		t.Fatalf("Failed to create auth service: %v", err)
	}

	// Create a user first
	existingUser := &database.User{
		ID:    uuid.New(),
		Sub:   "existing-subject-456",
		Email: "existing@example.com",
		Name:  "Existing User",
	}
	db.Create(existingUser)

	claims := map[string]any{
		"sub":   "existing-subject-456",
		"email": "new@example.com", // Different email
		"name":  "New Name",        // Different name
	}

	user, err := service.FindOrCreateUser("existing-subject-456", claims)
	if err != nil {
		t.Fatalf("Failed to find/create user: %v", err)
	}

	if user == nil {
		t.Fatal("User is nil")
	}

	// Should return existing user, not create new one
	if user.ID != existingUser.ID {
		t.Error("Should return existing user ID")
	}

	if user.Email != "existing@example.com" {
		t.Errorf("Should keep existing email, got '%s'", user.Email)
	}

	if user.Name != "Existing User" {
		t.Errorf("Should keep existing name, got '%s'", user.Name)
	}

	// Verify only one user exists
	var count int64
	db.Model(&database.User{}).Where("sub = ?", "existing-subject-456").Count(&count)
	if count != 1 {
		t.Errorf("Expected 1 user in database, got %d", count)
	}
}

func TestCreateSession(t *testing.T) {
	db := setupTestDB(t)
	service, err := NewAuthService(db)
	if err != nil {
		t.Fatalf("Failed to create auth service: %v", err)
	}

	// Create a user first
	user := &database.User{
		ID:    uuid.New(),
		Sub:   "test-subject",
		Email: "test@example.com",
		Name:  "Test User",
	}
	db.Create(user)

	session := &database.Session{
		ID:        "test-session-123",
		UserID:    user.ID,
		IDToken:   "test-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err = service.CreateSession(session)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Verify session was saved
	var savedSession database.Session
	err = db.Where("id = ?", "test-session-123").First(&savedSession).Error
	if err != nil {
		t.Fatalf("Failed to find saved session: %v", err)
	}

	if savedSession.UserID != user.ID {
		t.Error("Session user ID mismatch")
	}

	if savedSession.IDToken != "test-token" {
		t.Error("Session token mismatch")
	}
}

func TestFindSessionWithUser(t *testing.T) {
	db := setupTestDB(t)
	service, err := NewAuthService(db)
	if err != nil {
		t.Fatalf("Failed to create auth service: %v", err)
	}

	// Create user and session
	user := &database.User{
		ID:    uuid.New(),
		Sub:   "test-subject",
		Email: "test@example.com",
		Name:  "Test User",
	}
	db.Create(user)

	session := &database.Session{
		ID:        "test-session-456",
		UserID:    user.ID,
		IDToken:   "test-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	db.Create(session)

	// Test finding session with user
	foundSession, err := service.FindSessionWithUser("test-session-456")
	if err != nil {
		t.Fatalf("Failed to find session: %v", err)
	}

	if foundSession.ID != "test-session-456" {
		t.Error("Session ID mismatch")
	}

	if foundSession.User.ID != user.ID {
		t.Error("User not preloaded correctly")
	}

	if foundSession.User.Email != "test@example.com" {
		t.Error("User email not loaded correctly")
	}
}

func TestFindSessionWithUser_Expired(t *testing.T) {
	db := setupTestDB(t)
	service, err := NewAuthService(db)
	if err != nil {
		t.Fatalf("Failed to create auth service: %v", err)
	}

	// Create user and expired session
	user := &database.User{
		ID:    uuid.New(),
		Sub:   "test-subject",
		Email: "test@example.com",
		Name:  "Test User",
	}
	db.Create(user)

	expiredSession := &database.Session{
		ID:        "expired-session",
		UserID:    user.ID,
		IDToken:   "test-token",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}
	db.Create(expiredSession)

	// Should not find expired session
	_, err = service.FindSessionWithUser("expired-session")
	if err == nil {
		t.Error("Should not find expired session")
	}
}

func TestDeleteSession(t *testing.T) {
	db := setupTestDB(t)
	service, err := NewAuthService(db)
	if err != nil {
		t.Fatalf("Failed to create auth service: %v", err)
	}

	// Create user and session
	user := &database.User{
		ID:    uuid.New(),
		Sub:   "test-subject",
		Email: "test@example.com",
		Name:  "Test User",
	}
	db.Create(user)

	session := &database.Session{
		ID:        "session-to-delete",
		UserID:    user.ID,
		IDToken:   "test-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	db.Create(session)

	// Delete session
	err = service.DeleteSession("session-to-delete")
	if err != nil {
		t.Fatalf("Failed to delete session: %v", err)
	}

	// Verify session was deleted
	var count int64
	db.Model(&database.Session{}).Where("id = ?", "session-to-delete").Count(&count)
	if count != 0 {
		t.Errorf("Expected 0 sessions after deletion, got %d", count)
	}
}

func TestFindUser(t *testing.T) {
	db := setupTestDB(t)
	service, err := NewAuthService(db)
	if err != nil {
		t.Fatalf("Failed to create auth service: %v", err)
	}

	// Create user
	userID := uuid.New()
	user := &database.User{
		ID:    userID,
		Sub:   "test-subject",
		Email: "test@example.com",
		Name:  "Test User",
	}
	db.Create(user)

	// Find user
	foundUser, err := service.FindUser(userID)
	if err != nil {
		t.Fatalf("Failed to find user: %v", err)
	}

	if foundUser.ID != userID {
		t.Error("User ID mismatch")
	}

	if foundUser.Email != "test@example.com" {
		t.Error("User email mismatch")
	}
}

func TestGetConfig(t *testing.T) {
	db := setupTestDB(t)
	service, err := NewAuthService(db)
	if err != nil {
		t.Fatalf("Failed to create auth service: %v", err)
	}

	config := service.GetConfig()
	if config == nil {
		t.Fatal("Config is nil")
	}

	if config.IssuerURL != "http://localhost:5556" {
		t.Errorf("Expected IssuerURL 'http://localhost:5556', got '%s'", config.IssuerURL)
	}

	if config.ClientID != "bifrost-client" {
		t.Errorf("Expected ClientID 'bifrost-client', got '%s'", config.ClientID)
	}

	if config.ClientSecret != "bifrost-secret" {
		t.Errorf("Expected ClientSecret 'bifrost-secret', got '%s'", config.ClientSecret)
	}

	if config.RedirectURI != "http://localhost:8080/callback" {
		t.Errorf("Expected RedirectURI 'http://localhost:8080/callback', got '%s'", config.RedirectURI)
	}
}
