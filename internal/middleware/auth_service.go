package middleware

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"time"

	"bifrost-gov/internal/database"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// OIDCConfig contains OIDC provider configuration
type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

// AuthService handles core authentication operations
type AuthService struct {
	db       *gorm.DB
	verifier *oidc.IDTokenVerifier
	config   *OIDCConfig
}

// NewAuthService creates a new authentication service
func NewAuthService(db *gorm.DB) (*AuthService, error) {
	// Auto-migrate models
	if err := db.AutoMigrate(&database.User{}, &database.Session{}); err != nil {
		return nil, fmt.Errorf("failed to migrate auth models: %w", err)
	}

	// OIDC configuration
	config := &OIDCConfig{
		IssuerURL:    "http://localhost:5556",
		ClientID:     "bifrost-client",
		ClientSecret: "bifrost-secret",
		RedirectURI:  "http://localhost:8080/callback",
	}

	// Create OIDC provider
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Create ID token verifier
	verifierConfig := &oidc.Config{
		ClientID: config.ClientID,
	}
	verifier := provider.Verifier(verifierConfig)

	return &AuthService{
		db:       db,
		verifier: verifier,
		config:   config,
	}, nil
}

// FindOrCreateUser finds existing user or creates new one from OIDC claims
func (s *AuthService) FindOrCreateUser(sub string, claims map[string]any) (*database.User, error) {
	user := &database.User{}
	// Use silent mode to avoid logging "record not found" for user lookups
	err := s.db.Session(&gorm.Session{Logger: s.db.Logger.LogMode(logger.Silent)}).Where("sub = ?", sub).First(user).Error

	if err == nil {
		// User exists, update their details but preserve admin status
		email, _ := claims["email"].(string)
		name, _ := claims["name"].(string)

		// Update user details if they've changed, and check for admin privileges
		updated := false
		if user.Email != email && email != "" {
			user.Email = email
			updated = true
		}
		if user.Name != name && name != "" {
			user.Name = name
			updated = true
		}

		// Note: Admin privileges are only granted during initial seeding, not on every login
		// This prevents privilege escalation attacks via environment variable manipulation

		if updated {
			if err := s.db.Save(user).Error; err != nil {
				return nil, fmt.Errorf("failed to update user details: %w", err)
			}
			log.Printf("Updated user details for: %s (%s)", user.Email, user.ID)
		}

		return user, nil
	}

	if err != gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("failed to query user: %w", err)
	}

	// Create new user
	newEmail, _ := claims["email"].(string)
	newName, _ := claims["name"].(string)

	// Check if this user should be granted admin privileges
	initialAdminEmail := os.Getenv("INITIAL_ADMIN_EMAIL")
	isInitialAdmin := initialAdminEmail != "" && newEmail == initialAdminEmail

	user = &database.User{
		ID:      uuid.New(),
		Sub:     sub,
		Email:   newEmail,
		Name:    newName,
		IsAdmin: isInitialAdmin,
	}

	if isInitialAdmin {
		log.Printf("Granting admin privileges to initial admin user: %s", newEmail)
	}

	if err := s.db.Create(user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	log.Printf("Created new user: %s (%s)", user.Email, user.ID)
	return user, nil
}

// VerifyIDToken verifies an OIDC ID token and returns claims
func (s *AuthService) VerifyIDToken(tokenString string) (map[string]any, error) {
	ctx := context.Background()
	idToken, err := s.verifier.Verify(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse token claims: %w", err)
	}

	return claims, nil
}

// CreateSession creates a new session in the database
func (s *AuthService) CreateSession(session *database.Session) error {
	return s.db.Create(session).Error
}

// FindSessionWithUser finds a session with preloaded user by ID
func (s *AuthService) FindSessionWithUser(sessionID string) (*database.Session, error) {
	session := &database.Session{}
	err := s.db.Preload("User").Where("id = ? AND expires_at > ?", sessionID, time.Now()).First(session).Error
	return session, err
}

// DeleteSession deletes a session by ID
func (s *AuthService) DeleteSession(sessionID string) error {
	return s.db.Where("id = ?", sessionID).Delete(&database.Session{}).Error
}

// FindSession finds a session by ID (without expiry check)
func (s *AuthService) FindSession(sessionID string) (*database.Session, error) {
	session := &database.Session{}
	err := s.db.Where("id = ? AND expires_at > ?", sessionID, time.Now()).First(session).Error
	return session, err
}

// FindUser finds a user by ID
func (s *AuthService) FindUser(userID uuid.UUID) (*database.User, error) {
	user := &database.User{}
	err := s.db.Where("id = ?", userID).First(user).Error
	return user, err
}

// GetConfig returns the OIDC configuration
func (s *AuthService) GetConfig() *OIDCConfig {
	return s.config
}

// IsUserAdmin checks if a user has admin privileges
func (s *AuthService) IsUserAdmin(userID uuid.UUID) (bool, error) {
	user := &database.User{}
	err := s.db.Where("id = ?", userID).First(user).Error
	if err != nil {
		return false, err
	}
	return user.IsAdmin, nil
}

// isValidEmail validates email format
func isValidEmail(email string) bool {
	if email == "" {
		return false
	}
	// RFC 5322 compliant regex (simplified)
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email) && len(email) <= 254
}

// SeedInitialAdmin creates or updates the initial admin user based on environment variable
// This is a one-time operation that should only run during application startup
func (s *AuthService) SeedInitialAdmin() error {
	initialAdminEmail := os.Getenv("INITIAL_ADMIN_EMAIL")
	if initialAdminEmail == "" {
		log.Println("No INITIAL_ADMIN_EMAIL environment variable set, skipping admin user seeding")
		return nil
	}

	// Validate email format
	if !isValidEmail(initialAdminEmail) {
		return fmt.Errorf("INITIAL_ADMIN_EMAIL has invalid email format: %s", initialAdminEmail)
	}

	log.Printf("ADMIN_SEED: Seeding initial admin user with email: %s", initialAdminEmail)

	// Check if user already exists by email
	user := &database.User{}
	err := s.db.Where("email = ?", initialAdminEmail).First(user).Error
	
	if err == nil {
		// User exists, ensure they are admin
		if !user.IsAdmin {
			user.IsAdmin = true
			if err := s.db.Save(user).Error; err != nil {
				return fmt.Errorf("failed to update user to admin: %w", err)
			}
			log.Printf("ADMIN_GRANT: Updated existing user %s (%s) to admin", user.Email, user.ID)
		} else {
			log.Printf("ADMIN_SEED: User %s (%s) is already an admin", user.Email, user.ID)
		}
		return nil
	}

	if err != gorm.ErrRecordNotFound {
		return fmt.Errorf("failed to query for initial admin user: %w", err)
	}

	// User doesn't exist yet - they will be made admin when they first log in
	log.Printf("ADMIN_SEED: User with email %s not found yet. They will be granted admin privileges when they first log in via OIDC.", initialAdminEmail)
	return nil
}
