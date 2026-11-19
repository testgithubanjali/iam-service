package services

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"iam-service/internal/utils"

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

func (s *AuthService) Login(
	ctx context.Context,
	email string,
	password string,
) (*models.User, *utils.TokenPair, error) {

	email = strings.ToLower(strings.TrimSpace(email))

	user, passwordHash, err := s.UserRepo.FindByEmail(ctx, email)

	if err != nil {
		fmt.Println("DEBUG: FindByEmail failed:", err)
		return nil, nil, errors.New("invalid email or password")
	}

	fmt.Println("DEBUG: User found:", user.Email)
	fmt.Println("DEBUG: Password hash retrieved:", passwordHash != "")

	err = bcrypt.CompareHashAndPassword(
		[]byte(passwordHash),
		[]byte(password),
	)

	if err != nil {
		fmt.Println("DEBUG: Bcrypt comparison failed:", err)
		return nil, nil, errors.New("invalid email or password")
	}

	fmt.Println("DEBUG: Password comparison successful")

	tokens, err := utils.GenerateTokenPair(user.ID)
	if err != nil {
		return nil, nil, err
	}

	return user, tokens, nil
}
func (s *AuthService) Refresh(
	ctx context.Context,
	refreshToken string,
) (*models.User, *utils.TokenPair, error) {

	userID, err := utils.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, nil, err
	}

	user, err := s.UserRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, nil, errors.New("user not found")
	}

	tokens, err := utils.GenerateTokenPair(user.ID)
	if err != nil {
		return nil, nil, err
	}

	return user, tokens, nil
}
