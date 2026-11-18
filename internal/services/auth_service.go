package services

import (
	"context"
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"iam-service/internal/models"
	"iam-service/internal/repositories"
)

var ErrEmailAlreadyExists = errors.New("email already registered")

type AuthService struct {
	UserRepo *repositories.UserRepository
}

func NewAuthService(repo *repositories.UserRepository) *AuthService {
	return &AuthService{
		UserRepo: repo,
	}
}

func (s *AuthService) Register(
	ctx context.Context,
	name string,
	email string,
	password string,
) (*models.User, error) {

	name = strings.TrimSpace(name)
	email = strings.ToLower(strings.TrimSpace(email))

	if name == "" || email == "" || len(password) < 8 {
		return nil, errors.New("invalid registration details")
	}

	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return nil, err
	}

	user, err := s.UserRepo.Create(
		ctx,
		name,
		email,
		string(passwordHash),
	)
	if err != nil {
		var pgErr interface {
			SQLState() string
		}

		if errors.As(err, &pgErr) && pgErr.SQLState() == "23505" {
			return nil, ErrEmailAlreadyExists
		}

		return nil, err
	}

	return user, nil
}
