package services

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"iam-service/internal/models"
	"iam-service/internal/utils"
)

// Mock User Repository
type MockUserRepository struct {
	User            *models.User
	PasswordHash    string
	CreatedName     string
	CreatedEmail    string
	CreateError     error
	PasswordUpdated bool
}

func (m *MockUserRepository) Create(
	ctx context.Context,
	name, email, passwordHash string,
) (*models.User, error) {
	m.CreatedName = name
	m.CreatedEmail = email
	m.PasswordHash = passwordHash

	if m.CreateError != nil {
		return nil, m.CreateError
	}

	return m.User, nil
}

func (m *MockUserRepository) FindByEmail(
	ctx context.Context,
	email string,
) (*models.User, string, error) {
	return m.User, m.PasswordHash, nil
}

func (m *MockUserRepository) GetByID(
	ctx context.Context,
	id int64,
) (*models.User, error) {
	return m.User, nil
}

func (m *MockUserRepository) UpdateProfile(
	ctx context.Context,
	userID int64,
	name, email string,
) (*models.User, error) {
	return m.User, nil
}

func (m *MockUserRepository) FindByUserID(
	ctx context.Context,
	userID int64,
) (*models.User, string, error) {
	return m.User, m.PasswordHash, nil
}

func (m *MockUserRepository) UpdatePasswordAndRevokeTokens(
	ctx context.Context,
	userID int64,
	passwordHash string,
) error {
	m.PasswordHash = passwordHash
	m.PasswordUpdated = true
	return nil
}

// Mock Refresh Token Repository
type MockRefreshTokenRepository struct {
	SavedToken      string
	ValidatedUserID int64
	RotatedOldToken string
	RotatedNewToken string
	RevokedToken    string
}

func (m *MockRefreshTokenRepository) SaveRefreshToken(
	ctx context.Context,
	userID int64,
	token string,
	expiresAt time.Time,
) error {
	m.SavedToken = token
	return nil
}

func (m *MockRefreshTokenRepository) ValidateRefreshToken(
	ctx context.Context,
	token string,
) (int64, error) {
	return m.ValidatedUserID, nil
}

func (m *MockRefreshTokenRepository) RevokeRefreshToken(
	ctx context.Context,
	token string,
) error {
	m.RevokedToken = token
	return nil
}

func (m *MockRefreshTokenRepository) RotateRefreshToken(
	ctx context.Context,
	userID int64,
	oldToken, newToken string,
	expiresAt time.Time,
) error {
	m.RotatedOldToken = oldToken
	m.RotatedNewToken = newToken
	return nil
}

// Test Register
func TestRegister(t *testing.T) {
	user := &models.User{
		ID:   1,
		Role: "user",
	}

	userRepo := &MockUserRepository{
		User: user,
	}

	tokenRepo := &MockRefreshTokenRepository{}

	service := NewAuthService(userRepo, tokenRepo)

	result, err := service.Register(
		context.Background(),
		"  Anjali  ",
		" ANJALI@EXAMPLE.COM ",
		"Password123",
	)

	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected user, got nil")
	}

	if userRepo.CreatedName != "Anjali" {
		t.Errorf("Expected name Anjali, got %s", userRepo.CreatedName)
	}

	if userRepo.CreatedEmail != "anjali@example.com" {
		t.Errorf("Email was not normalized: %s", userRepo.CreatedEmail)
	}

	err = bcrypt.CompareHashAndPassword(
		[]byte(userRepo.PasswordHash),
		[]byte("Password123"),
	)

	if err != nil {
		t.Error("Password was not hashed correctly")
	}
}

// Test Register with invalid details
func TestRegisterInvalidDetails(t *testing.T) {
	userRepo := &MockUserRepository{}
	tokenRepo := &MockRefreshTokenRepository{}

	service := NewAuthService(userRepo, tokenRepo)

	_, err := service.Register(
		context.Background(),
		"",
		"anjali@example.com",
		"Password123",
	)

	if err == nil {
		t.Fatal("Expected error for invalid registration details")
	}
}

// Test Login with correct password
func TestLogin(t *testing.T) {
	t.Setenv("JWT_SECRET", strings.Repeat("a", 32))

	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte("Password123"),
		bcrypt.DefaultCost,
	)
	if err != nil {
		t.Fatal(err)
	}

	userRepo := &MockUserRepository{
		User: &models.User{
			ID:   1,
			Role: "user",
		},
		PasswordHash: string(passwordHash),
	}

	tokenRepo := &MockRefreshTokenRepository{}

	service := NewAuthService(userRepo, tokenRepo)

	user, tokens, err := service.Login(
		context.Background(),
		" ANJALI@EXAMPLE.COM ",
		"Password123",
	)

	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if user == nil || tokens == nil {
		t.Fatal("Expected user and tokens")
	}

	if tokens.AccessToken == "" {
		t.Error("Access token was not generated")
	}

	if tokens.RefreshToken == "" {
		t.Error("Refresh token was not generated")
	}

	if tokenRepo.SavedToken == "" {
		t.Error("Refresh token was not saved")
	}
}

// Test Login with incorrect password
func TestLoginWrongPassword(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte("Password123"),
		bcrypt.DefaultCost,
	)
	if err != nil {
		t.Fatal(err)
	}

	userRepo := &MockUserRepository{
		User: &models.User{
			ID:   1,
			Role: "user",
		},
		PasswordHash: string(passwordHash),
	}

	tokenRepo := &MockRefreshTokenRepository{}

	service := NewAuthService(userRepo, tokenRepo)

	_, tokens, err := service.Login(
		context.Background(),
		"anjali@example.com",
		"WrongPassword",
	)

	if err == nil {
		t.Fatal("Expected error for incorrect password")
	}

	if tokens != nil {
		t.Error("Expected no tokens for incorrect password")
	}

	if tokenRepo.SavedToken != "" {
		t.Error("Token should not be saved for failed login")
	}
}

// Test Refresh Token Rotation
func TestRefreshTokenRotation(t *testing.T) {
	t.Setenv("JWT_SECRET", strings.Repeat("a", 32))

	oldTokens, err := utils.GenerateTokenPair(1, "user")
	if err != nil {
		t.Fatal(err)
	}

	userRepo := &MockUserRepository{
		User: &models.User{
			ID:   1,
			Role: "user",
		},
	}

	tokenRepo := &MockRefreshTokenRepository{
		ValidatedUserID: 1,
	}

	service := NewAuthService(userRepo, tokenRepo)

	user, newTokens, err := service.Refresh(
		context.Background(),
		oldTokens.RefreshToken,
	)

	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	if user == nil || newTokens == nil {
		t.Fatal("Expected user and new tokens")
	}

	if newTokens.RefreshToken == oldTokens.RefreshToken {
		t.Error("Expected a new refresh token")
	}

	if tokenRepo.RotatedOldToken != oldTokens.RefreshToken {
		t.Error("Old token was not passed for rotation")
	}

	if tokenRepo.RotatedNewToken != newTokens.RefreshToken {
		t.Error("New token was not passed for rotation")
	}
}

// Test Logout
func TestLogout(t *testing.T) {
	t.Setenv("JWT_SECRET", strings.Repeat("a", 32))

	tokens, err := utils.GenerateTokenPair(1, "user")
	if err != nil {
		t.Fatal(err)
	}

	userRepo := &MockUserRepository{}
	tokenRepo := &MockRefreshTokenRepository{}

	service := NewAuthService(userRepo, tokenRepo)

	err = service.Logout(
		context.Background(),
		tokens.RefreshToken,
	)

	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	if tokenRepo.RevokedToken != tokens.RefreshToken {
		t.Error("Refresh token was not revoked")
	}
}

// Test Change Password successfully
func TestChangePassword(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte("OldPassword123"),
		bcrypt.DefaultCost,
	)
	if err != nil {
		t.Fatal(err)
	}

	userRepo := &MockUserRepository{
		User: &models.User{
			ID:   1,
			Role: "user",
		},
		PasswordHash: string(passwordHash),
	}

	tokenRepo := &MockRefreshTokenRepository{}

	service := NewAuthService(userRepo, tokenRepo)

	err = service.ChangePassword(
		context.Background(),
		1,
		"OldPassword123",
		"NewPassword123",
	)

	if err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	if !userRepo.PasswordUpdated {
		t.Fatal("Expected password to be updated")
	}

	err = bcrypt.CompareHashAndPassword(
		[]byte(userRepo.PasswordHash),
		[]byte("NewPassword123"),
	)

	if err != nil {
		t.Error("New password was not hashed correctly")
	}
}

// Test Change Password with incorrect current password
func TestChangePasswordWrongCurrentPassword(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte("OldPassword123"),
		bcrypt.DefaultCost,
	)
	if err != nil {
		t.Fatal(err)
	}

	userRepo := &MockUserRepository{
		User: &models.User{
			ID:   1,
			Role: "user",
		},
		PasswordHash: string(passwordHash),
	}

	service := NewAuthService(
		userRepo,
		&MockRefreshTokenRepository{},
	)

	err = service.ChangePassword(
		context.Background(),
		1,
		"WrongPassword123",
		"NewPassword123",
	)

	if err == nil {
		t.Fatal("Expected error for incorrect current password")
	}

	if userRepo.PasswordUpdated {
		t.Error("Password should not be updated")
	}
}

// Test Change Password with weak password
func TestChangePasswordWeakPassword(t *testing.T) {
	userRepo := &MockUserRepository{
		User: &models.User{
			ID:   1,
			Role: "user",
		},
	}

	service := NewAuthService(
		userRepo,
		&MockRefreshTokenRepository{},
	)

	err := service.ChangePassword(
		context.Background(),
		1,
		"OldPassword123",
		"12345",
	)

	if err == nil {
		t.Fatal("Expected error for weak password")
	}

	if userRepo.PasswordUpdated {
		t.Error("Password should not be updated")
	}
}
