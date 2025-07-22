package auth

import (
	"fmt"
	"log"

	"bifrost-gov/internal/database"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// UserService handles user creation and lookup operations
type UserService struct {
	db *gorm.DB
}

// NewUserService creates a new user service
func NewUserService(db *gorm.DB) *UserService {
	return &UserService{db: db}
}

// FindOrCreateUser finds existing user or creates new one from OIDC claims
func (s *UserService) FindOrCreateUser(sub string, claims map[string]any) (*database.User, error) {
	user := &database.User{}
	err := s.db.Where("sub = ?", sub).First(user).Error

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
