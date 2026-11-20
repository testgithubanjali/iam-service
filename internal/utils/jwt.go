package utils

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenClaims struct {
	UserID    int64  `json:"user_id"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func GenerateTokenPair(userID int64) (*TokenPair, error) {
	secret := os.Getenv("JWT_SECRET")

	if len(secret) < 32 {
		return nil, errors.New("JWT_SECRET must contain at least 32 characters")
	}

	accessToken, err := generateToken(userID, "access", 15*time.Minute, secret)
	if err != nil {
		return nil, err
	}

	refreshToken, err := generateToken(userID, "refresh", 7*24*time.Hour, secret)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func generateToken(
	userID int64,
	tokenType string,
	duration time.Duration,
	secret string,
) (string, error) {

	now := time.Now()

	// Generate a unique ID for every JWT
	jtiBytes := make([]byte, 16)

	_, err := rand.Read(jtiBytes)
	if err != nil {
		return "", err
	}

	jti := hex.EncodeToString(jtiBytes)

	claims := TokenClaims{
		UserID:    userID,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    "iam-service",
			Subject:   fmt.Sprintf("%d", userID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(secret))
}

func ValidateRefreshToken(refreshToken string) (int64, error) {
	secret := os.Getenv("JWT_SECRET")

	if len(secret) < 32 {
		return 0, errors.New("JWT_SECRET must contain at least 32 characters")
	}

	claims := &TokenClaims{}

	token, err := jwt.ParseWithClaims(
		refreshToken,
		claims,
		func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, jwt.ErrSignatureInvalid
			}

			return []byte(secret), nil
		},
		jwt.WithIssuer("iam-service"),
		jwt.WithExpirationRequired(),
	)

	if err != nil || token == nil || !token.Valid {
		return 0, errors.New("invalid or expired refresh token")
	}

	if claims.TokenType != "refresh" {
		return 0, errors.New("refresh token required")
	}

	if claims.UserID <= 0 {
		return 0, errors.New("invalid user ID")
	}

	return claims.UserID, nil
}
