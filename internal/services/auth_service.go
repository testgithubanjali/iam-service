package services

import (
	"context"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"iam-service/internal/models"
	"iam-service/internal/utils"
)

var ErrEmailAlreadyExists = errors.New("email already registered")

type UserRepository interface {
	Create(ctx context.Context, name, email, passwordHash string) (*models.User, error)
	FindByEmail(ctx context.Context, email string) (*models.User, string, error)
	GetByID(ctx context.Context, id int64) (*models.User, error)
	UpdateProfile(ctx context.Context, userID int64, name, email string) (*models.User, error)
	FindByUserID(ctx context.Context, userID int64) (*models.User, string, error)
	UpdatePasswordAndRevokeTokens(ctx context.Context, userID int64, passwordHash string) error
}

type RefreshTokenRepository interface {
	SaveRefreshToken(ctx context.Context, userID int64, token string, expiresAt time.Time) error
	ValidateRefreshToken(ctx context.Context, token string) (int64, error)
	RevokeRefreshToken(ctx context.Context, token string) error
	RotateRefreshToken(ctx context.Context, userID int64, oldToken, newToken string, expiresAt time.Time) error
}

type AuthService struct {
	UserRepo         UserRepository
	RefreshTokenRepo RefreshTokenRepository
}

func NewAuthService(
	userRepo UserRepository,
	refreshTokenRepo RefreshTokenRepository,
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

	// Generate access and refresh tokens with the user's role.
	tokens, err := utils.GenerateTokenPair(user.ID, user.Role)
	if err != nil {
		return nil, nil, err
	}

	// Save refresh-token hash in PostgreSQL.
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

	// 1. Validate JWT signature, expiry and token type.
	userID, err := utils.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, nil, err
	}

	// 2. Validate refresh token in PostgreSQL.
	storedUserID, err := s.RefreshTokenRepo.ValidateRefreshToken(
		ctx,
		refreshToken,
	)
	if err != nil {
		return nil, nil, err
	}

	if storedUserID != userID {
		return nil, nil, errors.New("invalid refresh token")
	}

	// 3. Get user details, including role.
	user, err := s.UserRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, nil, errors.New("user not found")
	}

	// 4. Generate new token pair with the current database role.
	tokens, err := utils.GenerateTokenPair(user.ID, user.Role)
	if err != nil {
		return nil, nil, err
	}

	// 5. Rotate tokens atomically in PostgreSQL.
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	err = s.RefreshTokenRepo.RotateRefreshToken(
		ctx,
		user.ID,
		refreshToken,
		tokens.RefreshToken,
		expiresAt,
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

	// 1. Find user and retrieve password hash.
	user, passwordHash, err := s.UserRepo.FindByUserID(ctx, userID)
	if err != nil {
		return errors.New("user not found")
	}

	// 2. Verify current password.
	err = bcrypt.CompareHashAndPassword(
		[]byte(passwordHash),
		[]byte(currentPassword),
	)
	if err != nil {
		return errors.New("current password is incorrect")
	}

	// 3. Generate new password hash.
	newPasswordHash, err := bcrypt.GenerateFromPassword(
		[]byte(newPassword),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return err
	}

	// 4. Update password and revoke all refresh tokens atomically.
	err = s.UserRepo.UpdatePasswordAndRevokeTokens(
		ctx,
		user.ID,
		string(newPasswordHash),
	)
	if err != nil {
		return err
	}

	return nil
}

func (s *AuthService) Logout(
	ctx context.Context,
	refreshToken string,
) error {

	// Validate JWT refresh token.
	_, err := utils.ValidateRefreshToken(refreshToken)
	if err != nil {
		return err
	}

	// Revoke token in PostgreSQL.
	err = s.RefreshTokenRepo.RevokeRefreshToken(
		ctx,
		refreshToken,
	)
	if err != nil {
		return err
	}

	return nil
}
