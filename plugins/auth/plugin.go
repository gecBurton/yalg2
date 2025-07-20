package auth

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/maximhq/bifrost/core/schemas"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// AuthPlugin implements OIDC-based authentication
type AuthPlugin struct {
	config   *OIDCConfig
	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider
	db       *gorm.DB
}

// NewAuthPlugin creates a new OIDC AuthPlugin
func NewAuthPlugin(config *OIDCConfig) (*AuthPlugin, error) {
	return NewAuthPluginWithDB(config, nil)
}

// NewAuthPluginWithDB creates a new OIDC AuthPlugin with an optional external database connection
func NewAuthPluginWithDB(config *OIDCConfig, externalDB *gorm.DB) (*AuthPlugin, error) {
	if config == nil {
		return nil, fmt.Errorf("OIDC config is required")
	}

	ctx := context.Background()

	// Create OIDC provider
	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Create ID token verifier
	verifierConfig := &oidc.Config{
		ClientID: config.ClientID,
	}
	if config.Audience != "" {
		verifierConfig.SupportedSigningAlgs = []string{"RS256", "ES256"}
	}

	verifier := provider.Verifier(verifierConfig)

	// Use external database or create new connection
	var db *gorm.DB
	if externalDB != nil {
		db = externalDB
	} else if config.DatabaseURL != "" {
		db, err = gorm.Open(postgres.Open(config.DatabaseURL), &gorm.Config{})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to database: %w", err)
		}
	}

	// Auto-migrate the User and Session tables if we have a database
	if db != nil {
		if err = db.AutoMigrate(&User{}, &Session{}); err != nil {
			return nil, fmt.Errorf("failed to auto-migrate User and Session tables: %w", err)
		}
	}

	return &AuthPlugin{
		config:   config,
		verifier: verifier,
		provider: provider,
		db:       db,
	}, nil
}

// GetName returns the name of the plugin
func (p *AuthPlugin) GetName() string {
	return "OIDCAuthPlugin"
}

// PreHook validates OIDC tokens before request processing
// Note: This is no longer used as we handle auth at the HTTP handler level
func (p *AuthPlugin) PreHook(ctx *context.Context, req *schemas.BifrostRequest) (*schemas.BifrostRequest, *schemas.PluginShortCircuit, error) {
	// No-op: Authentication is now handled by AuthCompletionHandler
	return req, nil, nil
}

// PostHook is called after a response is received from a provider
func (p *AuthPlugin) PostHook(ctx *context.Context, result *schemas.BifrostResponse, err *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError, error) {
	// No post-processing needed for auth
	return result, err, nil
}

// Cleanup is called on bifrost shutdown
func (p *AuthPlugin) Cleanup() error {
	if p.db != nil {
		sqlDB, err := p.db.DB()
		if err != nil {
			return err
		}
		return sqlDB.Close()
	}
	return nil
}

// GetDB returns the database connection for use by other components
func (p *AuthPlugin) GetDB() *gorm.DB {
	return p.db
}

// GetVerifier returns the OIDC verifier for use by auth handlers
func (p *AuthPlugin) GetVerifier() *oidc.IDTokenVerifier {
	return p.verifier
}

// insertOrUpdateUser inserts a new user or updates existing user in the database
func (p *AuthPlugin) insertOrUpdateUser(user *User) error {
	if p.db == nil {
		return nil // No database configured
	}

	// Check if user already exists
	var existingUser User
	result := p.db.Where("sub = ?", user.Sub).First(&existingUser)
	
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			// User doesn't exist, create new one
			return p.db.Create(user).Error
		}
		return result.Error
	}

	// User exists, update the fields while keeping the original ID
	user.ID = existingUser.ID
	return p.db.Model(&existingUser).Where("id = ?", existingUser.ID).Updates(User{
		Email: user.Email,
		Name:  user.Name,
	}).Error
}

// InsertOrUpdateUser is a public method to allow external use
func (p *AuthPlugin) InsertOrUpdateUser(user *User) error {
	return p.insertOrUpdateUser(user)
}

// CreateSession creates a new session in the database
func (p *AuthPlugin) CreateSession(session *Session) error {
	if p.db == nil {
		return fmt.Errorf("database not available")
	}
	return p.db.Create(session).Error
}

// GetSession retrieves a session from the database by ID
func (p *AuthPlugin) GetSession(sessionID string) (*Session, error) {
	if p.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	
	var session Session
	err := p.db.Preload("User").Where("id = ? AND expires_at > ?", sessionID, time.Now()).First(&session).Error
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// DeleteSession removes a session from the database
func (p *AuthPlugin) DeleteSession(sessionID string) error {
	if p.db == nil {
		return fmt.Errorf("database not available")
	}
	return p.db.Delete(&Session{}, "id = ?", sessionID).Error
}

// CleanupExpiredSessions removes expired sessions from the database
func (p *AuthPlugin) CleanupExpiredSessions() error {
	if p.db == nil {
		return fmt.Errorf("database not available")
	}
	return p.db.Delete(&Session{}, "expires_at <= ?", time.Now()).Error
}

// extractAuthHeader extracts the Authorization header from context
func (p *AuthPlugin) extractAuthHeader(ctx *context.Context) string {
	// First try the standard Authorization header
	if value := (*ctx).Value("Authorization"); value != nil {
		if auth, ok := value.(string); ok {
			return auth
		}
	}
	
	// Try our custom header that gets processed by Bifrost context conversion
	if value := (*ctx).Value("auth-token"); value != nil {
		if token, ok := value.(string); ok {
			return "Bearer " + token
		}
	}
	
	return ""
}

// validateToken validates an OIDC ID token and stores user information
func (p *AuthPlugin) validateToken(ctx *context.Context, tokenString string) error {
	// Verify OIDC ID token
	idToken, err := p.verifier.Verify(*ctx, tokenString)
	if err != nil {
		return fmt.Errorf("token verification failed: %w", err)
	}

	// Extract claims
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return fmt.Errorf("failed to extract claims: %w", err)
	}

	// Validate audience if configured
	if p.config.Audience != "" {
		if aud, ok := claims["aud"].(string); !ok || aud != p.config.Audience {
			return fmt.Errorf("invalid audience")
		}
	}

	// Extract user information from claims
	user := &User{}

	if sub, ok := claims["sub"].(string); ok {
		user.Sub = sub
	} else {
		return fmt.Errorf("missing subject claim")
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
	if err := p.insertOrUpdateUser(user); err != nil {
		// Log error but don't fail authentication
		log.Printf("Warning: failed to store user in database: %v", err)
	} else {
		// Store user ID in context for logging plugin
		*ctx = context.WithValue(*ctx, "user_id", user.ID)
		*ctx = context.WithValue(*ctx, "user_sub", user.Sub)
	}

	return nil
}