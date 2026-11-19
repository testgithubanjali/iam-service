package services

import (
	"context"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"iam-service/internal/models"
	"iam-service/internal/repositories"
	"iam-service/internal/utils"
)

var ErrEmailAlreadyExists = errors.New("email already registered")

type AuthService struct {
	UserRepo         *repositories.UserRepository
	RefreshTokenRepo *repositories.RefreshTokenRepository
}

func NewAuthService(
	userRepo *repositories.UserRepository,
	refreshTokenRepo *repositories.RefreshTokenRepository,
) *AuthService {
	return &AuthService{
		UserRepo:         userRepo,
		RefreshTokenRepo: refreshTokenRepo,
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
		return nil, nil, errors.New("invalid email or password")
	}

	err = bcrypt.CompareHashAndPassword(
		[]byte(passwordHash),
		[]byte(password),
	)
	if err != nil {
		return nil, nil, errors.New("invalid email or password")
	}

	// Generate access and refresh tokens
	tokens, err := utils.GenerateTokenPair(user.ID)
	if err != nil {
		return nil, nil, err
	}

	// Save refresh-token hash in PostgreSQL
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	err = s.RefreshTokenRepo.SaveRefreshToken(
		ctx,
		user.ID,
		tokens.RefreshToken,
		expiresAt,
	)
	if err != nil {
		return nil, nil, err
	}

	return user, tokens, nil
}

func (s *AuthService) Refresh(
	ctx context.Context,
	refreshToken string,
) (*models.User, *utils.TokenPair, error) {

	// 1. Validate JWT signature, expiry and token type
	userID, err := utils.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, nil, err
	}

	// 2. Check whether the refresh token exists in PostgreSQL
	storedUserID, err := s.RefreshTokenRepo.ValidateRefreshToken(
		ctx,
		refreshToken,
	)
	if err != nil {
		return nil, nil, err
	}

	// 3. Ensure the database user ID matches the JWT user ID
	if storedUserID != userID {
		return nil, nil, errors.New("invalid refresh token")
	}

	// 4. Get user details
	user, err := s.UserRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, nil, errors.New("user not found")
	}

	// 5. Generate a new token pair
	tokens, err := utils.GenerateTokenPair(user.ID)
	if err != nil {
		return nil, nil, err
	}

	// 6. Save the new refresh token in PostgreSQL
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	err = s.RefreshTokenRepo.SaveRefreshToken(
		ctx,
		user.ID,
		tokens.RefreshToken,
		expiresAt,
	)
	if err != nil {
		return nil, nil, err
	}

	// 7. Revoke the old refresh token
	err = s.RefreshTokenRepo.RevokeRefreshToken(
		ctx,
		refreshToken,
	)
	if err != nil {
		return nil, nil, err
	}

	return user, tokens, nil
}
func (s *AuthService) UpdateProfile(
	ctx context.Context,
	userID int64,
	name string,
	email string,
) (*models.User, error) {

	name = strings.TrimSpace(name)
	email = strings.ToLower(strings.TrimSpace(email))

	if name == "" || email == "" {
		return nil, errors.New("name and email are required")
	}

	user, err := s.UserRepo.UpdateProfile(
		ctx,
		userID,
		name,
		email,
	)

	if err != nil {
		return nil, err
	}

	return user, nil
}
func (s *AuthService) ChangePassword(
	ctx context.Context,
	userID int64,
	currentPassword string,
	newPassword string,
) error {

	if len(newPassword) < 8 {
		return errors.New("new password must be at least 8 characters")
	}

	if currentPassword == newPassword {
		return errors.New("new password must be different")
	}

	user, passwordHash, err := s.UserRepo.FindByUserID(ctx, userID)
	if err != nil {
		return errors.New("user not found")
	}

	err = bcrypt.CompareHashAndPassword(
		[]byte(passwordHash),
		[]byte(currentPassword),
	)
	if err != nil {
		return errors.New("current password is incorrect")
	}

	newPasswordHash, err := bcrypt.GenerateFromPassword(
		[]byte(newPassword),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return err
	}

	return s.UserRepo.UpdatePassword(
		ctx,
		user.ID,
		string(newPasswordHash),
	)
}
