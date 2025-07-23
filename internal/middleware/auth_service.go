package middleware

import (
	"context"
	"fmt"
	"log"
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
		return user, nil
	}

	if err != gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("failed to query user: %w", err)
	}

	// Create new user
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)

	user = &database.User{
		ID:    uuid.New(),
		Sub:   sub,
		Email: email,
		Name:  name,
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
