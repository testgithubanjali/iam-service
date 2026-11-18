
package utils

import (
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

	claims := TokenClaims{
		UserID:    userID,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "iam-service",
			Subject:   fmt.Sprintf("%d", userID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(secret))
}
