package auth

import (
	"context"
	"testing"
	"time"

	"bifrost-gov/internal/testutil"
	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	"gorm.io/gorm"
)

// createMockAuthPlugin creates a plugin with mocked OIDC components for testing
func createMockAuthPlugin(t *testing.T, db *gorm.DB) *AuthPlugin {
	config := &OIDCConfig{
		IssuerURL:   "http://mock-issuer.example.com",
		ClientID:    "mock-client-id",
		Audience:    "mock-audience",
		DatabaseURL: "",
	}

	// Create plugin with external DB (bypassing OIDC provider creation)
	plugin := &AuthPlugin{
		config:   config,
		verifier: nil, // We'll mock this for tests that need it
		provider: nil, // We'll mock this for tests that need it
		db:       db,
	}

	return plugin
}

func TestNewAuthPlugin_NilConfig(t *testing.T) {
	plugin, err := NewAuthPlugin(nil)

	if plugin != nil {
		t.Error("Expected nil plugin when config is nil")
	}
	if err == nil {
		t.Error("Expected error when config is nil")
	}

	expectedError := "OIDC config is required"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

func TestNewAuthPluginWithDB_NilConfig(t *testing.T) {
	db := testutil.SetupTestDB(t, &User{}, &Session{})
	plugin, err := NewAuthPluginWithDB(nil, db)

	if plugin != nil {
		t.Error("Expected nil plugin when config is nil")
	}
	if err == nil {
		t.Error("Expected error when config is nil")
	}

	expectedError := "OIDC config is required"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

func TestAuthPlugin_GetName(t *testing.T) {
	db := testutil.SetupTestDB(t, &User{}, &Session{})
	plugin := createMockAuthPlugin(t, db)

	name := plugin.GetName()
	expectedName := "OIDCAuthPlugin"
	if name != expectedName {
		t.Errorf("Expected plugin name '%s', got '%s'", expectedName, name)
	}
}

func TestAuthPlugin_GetDB(t *testing.T) {
	db := testutil.SetupTestDB(t, &User{}, &Session{})
	plugin := createMockAuthPlugin(t, db)

	resultDB := plugin.GetDB()
	if resultDB != db {
		t.Error("Expected GetDB to return the same database instance")
	}
}

func TestAuthPlugin_GetDB_NilDB(t *testing.T) {
	plugin := createMockAuthPlugin(t, nil)

	resultDB := plugin.GetDB()
	if resultDB != nil {
		t.Error("Expected GetDB to return nil when no database")
	}
}

func TestAuthPlugin_GetVerifier(t *testing.T) {
	db := testutil.SetupTestDB(t, &User{}, &Session{})
	plugin := createMockAuthPlugin(t, db)

	verifier := plugin.GetVerifier()
	// Since we're mocking, verifier will be nil
	if verifier != nil {
		t.Error("Expected GetVerifier to return nil in mock setup")
	}
}

func TestAuthPlugin_PreHook(t *testing.T) {
	db := testutil.SetupTestDB(t, &User{}, &Session{})
	plugin := createMockAuthPlugin(t, db)

	ctx := context.Background()
	req := &schemas.BifrostRequest{
		Model: "gpt-4",
	}

	result, shortCircuit, err := plugin.PreHook(&ctx, req)

	// PreHook is currently a no-op
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if shortCircuit != nil {
		t.Error("Expected no short circuit")
	}
	if result != req {
		t.Error("Expected request to be returned unchanged")
	}
}

func TestAuthPlugin_PostHook(t *testing.T) {
	db := testutil.SetupTestDB(t, &User{}, &Session{})
	plugin := createMockAuthPlugin(t, db)

	ctx := context.Background()
	response := &schemas.BifrostResponse{}
	bifrostErr := &schemas.BifrostError{}

	result, err, pluginErr := plugin.PostHook(&ctx, response, bifrostErr)

	// PostHook is currently a no-op
	if pluginErr != nil {
		t.Errorf("Expected no plugin error, got: %v", pluginErr)
	}
	if result != response {
		t.Error("Expected response to be returned unchanged")
	}
	if err != bifrostErr {
		t.Error("Expected bifrost error to be returned unchanged")
	}
}

func TestAuthPlugin_InsertOrUpdateUser_NewUser(t *testing.T) {
	db := testutil.SetupTestDB(t, &User{}, &Session{})
	plugin := createMockAuthPlugin(t, db)

	user := &User{
		Sub:   "user123",
		Email: "test@example.com",
		Name:  "Test User",
	}

	err := plugin.InsertOrUpdateUser(user)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Verify user was created
	var testUser User
	dbErr := db.Where("sub = ?", "user123").First(&testUser).Error
	if dbErr != nil {
		t.Fatalf("Expected user to be created: %v", dbErr)
	}

	if testUser.Sub != "user123" {
		t.Errorf("Expected sub 'user123', got '%s'", testUser.Sub)
	}
	if testUser.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", testUser.Email)
	}
	if testUser.Name != "Test User" {
		t.Errorf("Expected name 'Test User', got '%s'", testUser.Name)
	}
	if testUser.MaxRequestsPerMinute != 60 {
		t.Errorf("Expected default rate limit 60, got %d", testUser.MaxRequestsPerMinute)
	}
}

func TestAuthPlugin_InsertOrUpdateUser_UpdateExisting(t *testing.T) {
	db := testutil.SetupTestDB(t, &User{}, &Session{})
	plugin := createMockAuthPlugin(t, db)

	// Create initial user
	userID := uuid.New()
	initialUser := &User{
		ID:    userID,
		Sub:   "user456",
		Email: "old@example.com",
		Name:  "Old Name",
	}
	if err := db.Create(initialUser).Error; err != nil {
		t.Fatalf("Failed to create initial user: %v", err)
	}

	// Update user with same sub
	updatedUser := &User{
		Sub:   "user456",
		Email: "new@example.com",
		Name:  "New Name",
	}

	err := plugin.InsertOrUpdateUser(updatedUser)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Verify user was updated
	var testUser User
	dbErr := db.Where("sub = ?", "user456").First(&testUser).Error
	if dbErr != nil {
		t.Fatalf("Expected user to exist: %v", dbErr)
	}

	if testUser.Email != "new@example.com" {
		t.Errorf("Expected updated email 'new@example.com', got '%s'", testUser.Email)
	}
	if testUser.Name != "New Name" {
		t.Errorf("Expected updated name 'New Name', got '%s'", testUser.Name)
	}
	// ID should remain the same
	if testUser.ID != userID {
		t.Error("Expected user ID to remain unchanged")
	}
}

func TestAuthPlugin_InsertOrUpdateUser_NoDatabase(t *testing.T) {
	plugin := createMockAuthPlugin(t, nil)

	user := &User{
		Sub:   "user789",
		Email: "test@example.com",
		Name:  "Test User",
	}

	err := plugin.InsertOrUpdateUser(user)
	// Should not error when no database (no-op)
	if err != nil {
		t.Errorf("Expected no error when no database, got: %v", err)
	}
}

func TestAuthPlugin_CreateSession(t *testing.T) {
	db := testutil.SetupTestDB(t, &User{}, &Session{})
	plugin := createMockAuthPlugin(t, db)

	// Create a user first
	userID := uuid.New()
	user := &User{
		ID:   userID,
		Sub:  "session-user",
		Name: "Session User",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	session := &Session{
		ID:        "session123",
		UserID:    userID,
		IDToken:   "mock-id-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := plugin.CreateSession(session)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Verify session was created
	var testSession Session
	dbErr := db.Where("id = ?", "session123").First(&testSession).Error
	if dbErr != nil {
		t.Fatalf("Expected session to be created: %v", dbErr)
	}

	if testSession.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, testSession.UserID)
	}
	if testSession.IDToken != "mock-id-token" {
		t.Errorf("Expected ID token 'mock-id-token', got '%s'", testSession.IDToken)
	}
}

func TestAuthPlugin_CreateSession_NoDatabase(t *testing.T) {
	plugin := createMockAuthPlugin(t, nil)

	session := &Session{
		ID:        "session456",
		UserID:    uuid.New(),
		IDToken:   "mock-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := plugin.CreateSession(session)
	if err == nil {
		t.Error("Expected error when no database")
	}

	expectedError := "database not available"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

func TestAuthPlugin_GetSession(t *testing.T) {
	db := testutil.SetupTestDB(t, &User{}, &Session{})
	plugin := createMockAuthPlugin(t, db)

	// Create a user first
	userID := uuid.New()
	user := &User{
		ID:   userID,
		Sub:  "get-session-user",
		Name: "Get Session User",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Create a session
	expiresAt := time.Now().Add(24 * time.Hour)
	session := &Session{
		ID:        "get-session123",
		UserID:    userID,
		IDToken:   "get-mock-token",
		ExpiresAt: expiresAt,
	}
	if err := db.Create(session).Error; err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Test getting the session
	retrievedSession, err := plugin.GetSession("get-session123")
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if retrievedSession == nil {
		t.Fatal("Expected session to be retrieved")
	}
	if retrievedSession.ID != "get-session123" {
		t.Errorf("Expected session ID 'get-session123', got '%s'", retrievedSession.ID)
	}
	if retrievedSession.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, retrievedSession.UserID)
	}
	if retrievedSession.IDToken != "get-mock-token" {
		t.Errorf("Expected ID token 'get-mock-token', got '%s'", retrievedSession.IDToken)
	}

	// Test that User is preloaded
	if retrievedSession.User == nil {
		t.Error("Expected User to be preloaded")
	} else {
		if retrievedSession.User.ID != userID {
			t.Error("Expected preloaded user to have correct ID")
		}
	}
}

func TestAuthPlugin_GetSession_ExpiredSession(t *testing.T) {
	db := testutil.SetupTestDB(t, &User{}, &Session{})
	plugin := createMockAuthPlugin(t, db)

	// Create a user first
	userID := uuid.New()
	user := &User{
		ID:   userID,
		Sub:  "expired-session-user",
		Name: "Expired Session User",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Create an expired session
	session := &Session{
		ID:        "expired-session",
		UserID:    userID,
		IDToken:   "expired-token",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}
	if err := db.Create(session).Error; err != nil {
		t.Fatalf("Failed to create expired session: %v", err)
	}

	// Test getting the expired session
	retrievedSession, err := plugin.GetSession("expired-session")
	if err == nil {
		t.Error("Expected error for expired session")
	}
	if retrievedSession != nil {
		t.Error("Expected nil session for expired session")
	}
}

func TestAuthPlugin_GetSession_NotFound(t *testing.T) {
	db := testutil.SetupTestDB(t, &User{}, &Session{})
	plugin := createMockAuthPlugin(t, db)

	// Test getting non-existent session
	retrievedSession, err := plugin.GetSession("non-existent")
	if err == nil {
		t.Error("Expected error for non-existent session")
	}
	if retrievedSession != nil {
		t.Error("Expected nil session for non-existent session")
	}
}

func TestAuthPlugin_GetSession_NoDatabase(t *testing.T) {
	plugin := createMockAuthPlugin(t, nil)

	retrievedSession, err := plugin.GetSession("any-session")
	if err == nil {
		t.Error("Expected error when no database")
	}
	if retrievedSession != nil {
		t.Error("Expected nil session when no database")
	}

	expectedError := "database not available"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

func TestAuthPlugin_DeleteSession(t *testing.T) {
	db := testutil.SetupTestDB(t, &User{}, &Session{})
	plugin := createMockAuthPlugin(t, db)

	// Create a user first
	userID := uuid.New()
	user := &User{
		ID:   userID,
		Sub:  "delete-session-user",
		Name: "Delete Session User",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Create a session to delete
	session := &Session{
		ID:        "delete-session",
		UserID:    userID,
		IDToken:   "delete-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := db.Create(session).Error; err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Test deleting the session
	err := plugin.DeleteSession("delete-session")
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Verify session was deleted
	var testSession Session
	dbErr := db.Where("id = ?", "delete-session").First(&testSession).Error
	if dbErr == nil {
		t.Error("Expected session to be deleted")
	}
}

func TestAuthPlugin_DeleteSession_NoDatabase(t *testing.T) {
	plugin := createMockAuthPlugin(t, nil)

	err := plugin.DeleteSession("any-session")
	if err == nil {
		t.Error("Expected error when no database")
	}

	expectedError := "database not available"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

func TestAuthPlugin_CleanupExpiredSessions(t *testing.T) {
	db := testutil.SetupTestDB(t, &User{}, &Session{})
	plugin := createMockAuthPlugin(t, db)

	// Create a user first
	userID := uuid.New()
	user := &User{
		ID:   userID,
		Sub:  "cleanup-session-user",
		Name: "Cleanup Session User",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Create a valid session
	validSession := &Session{
		ID:        "valid-session",
		UserID:    userID,
		IDToken:   "valid-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := db.Create(validSession).Error; err != nil {
		t.Fatalf("Failed to create valid session: %v", err)
	}

	// Create an expired session
	expiredSession := &Session{
		ID:        "expired-session",
		UserID:    userID,
		IDToken:   "expired-token",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	if err := db.Create(expiredSession).Error; err != nil {
		t.Fatalf("Failed to create expired session: %v", err)
	}

	// Test cleanup
	err := plugin.CleanupExpiredSessions()
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Verify expired session was deleted
	var expiredTest Session
	expiredErr := db.Where("id = ?", "expired-session").First(&expiredTest).Error
	if expiredErr == nil {
		t.Error("Expected expired session to be deleted")
	}

	// Verify valid session still exists
	var validTest Session
	validErr := db.Where("id = ?", "valid-session").First(&validTest).Error
	if validErr != nil {
		t.Error("Expected valid session to still exist")
	}
}

func TestAuthPlugin_CleanupExpiredSessions_NoDatabase(t *testing.T) {
	plugin := createMockAuthPlugin(t, nil)

	err := plugin.CleanupExpiredSessions()
	if err == nil {
		t.Error("Expected error when no database")
	}

	expectedError := "database not available"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

func TestAuthPlugin_Cleanup_WithDatabase(t *testing.T) {
	db := testutil.SetupTestDB(t, &User{}, &Session{})
	plugin := createMockAuthPlugin(t, db)

	err := plugin.Cleanup()
	if err != nil {
		t.Errorf("Expected no error during cleanup, got: %v", err)
	}
}

func TestAuthPlugin_Cleanup_NoDatabase(t *testing.T) {
	plugin := createMockAuthPlugin(t, nil)

	err := plugin.Cleanup()
	if err != nil {
		t.Errorf("Expected no error during cleanup with nil db, got: %v", err)
	}
}

func TestAuthPlugin_ExtractAuthHeader(t *testing.T) {
	db := testutil.SetupTestDB(t, &User{}, &Session{})
	plugin := createMockAuthPlugin(t, db)

	// Test with Authorization header
	ctx := context.WithValue(context.Background(), "Authorization", "Bearer test-token")
	authHeader := plugin.extractAuthHeader(&ctx)
	if authHeader != "Bearer test-token" {
		t.Errorf("Expected 'Bearer test-token', got '%s'", authHeader)
	}

	// Test with auth-token header
	ctx2 := context.WithValue(context.Background(), "auth-token", "custom-token")
	authHeader2 := plugin.extractAuthHeader(&ctx2)
	if authHeader2 != "Bearer custom-token" {
		t.Errorf("Expected 'Bearer custom-token', got '%s'", authHeader2)
	}

	// Test with no auth headers
	ctx3 := context.Background()
	authHeader3 := plugin.extractAuthHeader(&ctx3)
	if authHeader3 != "" {
		t.Errorf("Expected empty string, got '%s'", authHeader3)
	}

	// Test with wrong type in context
	ctx4 := context.WithValue(context.Background(), "Authorization", 123)
	authHeader4 := plugin.extractAuthHeader(&ctx4)
	if authHeader4 != "" {
		t.Errorf("Expected empty string for wrong type, got '%s'", authHeader4)
	}
}

// TestCompleteUserWorkflow tests the complete user management workflow
func TestCompleteUserWorkflow(t *testing.T) {
	db := testutil.SetupTestDB(t, &User{}, &Session{})
	plugin := createMockAuthPlugin(t, db)

	// Step 1: Create a new user
	user := &User{
		Sub:   "workflow-user",
		Email: "workflow@example.com",
		Name:  "Workflow User",
	}

	err := plugin.InsertOrUpdateUser(user)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Step 2: Create a session for the user
	session := &Session{
		ID:        "workflow-session",
		UserID:    user.ID, // ID was set during user creation
		IDToken:   "workflow-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err = plugin.CreateSession(session)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Step 3: Retrieve the session
	retrievedSession, err := plugin.GetSession("workflow-session")
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	if retrievedSession.UserID != user.ID {
		t.Error("Session user ID mismatch")
	}
	if retrievedSession.User == nil {
		t.Error("User should be preloaded in session")
	} else if retrievedSession.User.Sub != "workflow-user" {
		t.Error("Preloaded user sub mismatch")
	}

	// Step 4: Update the user
	user.Email = "updated@example.com"
	user.Name = "Updated User"
	err = plugin.InsertOrUpdateUser(user)
	if err != nil {
		t.Fatalf("Failed to update user: %v", err)
	}

	// Step 5: Verify user was updated
	var updatedUser User
	dbErr := db.Where("sub = ?", "workflow-user").First(&updatedUser).Error
	if dbErr != nil {
		t.Fatalf("Failed to find updated user: %v", dbErr)
	}

	if updatedUser.Email != "updated@example.com" {
		t.Error("User email was not updated")
	}
	if updatedUser.Name != "Updated User" {
		t.Error("User name was not updated")
	}

	// Step 6: Delete the session
	err = plugin.DeleteSession("workflow-session")
	if err != nil {
		t.Fatalf("Failed to delete session: %v", err)
	}

	// Step 7: Verify session was deleted
	_, err = plugin.GetSession("workflow-session")
	if err == nil {
		t.Error("Expected error when getting deleted session")
	}
}