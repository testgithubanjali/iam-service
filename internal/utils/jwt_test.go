package utils

import (
	"testing"
)

func TestGenerateTokenPair(t *testing.T) {
	t.Setenv("JWT_SECRET", "this-is-a-test-secret-key-at-least-32-characters")

	tokens, err := GenerateTokenPair(1, "user")

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if tokens.AccessToken == "" {
		t.Fatal("Access token should not be empty")
	}

	if tokens.RefreshToken == "" {
		t.Fatal("Refresh token should not be empty")
	}

	if tokens.AccessToken == tokens.RefreshToken {
		t.Fatal("Access and refresh tokens should be different")
	}
}

func TestValidateRefreshToken(t *testing.T) {
	t.Setenv("JWT_SECRET", "this-is-a-test-secret-key-at-least-32-characters")

	tokens, err := GenerateTokenPair(1, "user")
	if err != nil {
		t.Fatalf("Token generation failed: %v", err)
	}

	userID, err := ValidateRefreshToken(tokens.RefreshToken)

	if err != nil {
		t.Fatalf("Expected valid refresh token, got %v", err)
	}

	if userID != 1 {
		t.Errorf("Expected user ID 1, got %d", userID)
	}
}

func TestValidateAccessTokenAsRefreshToken(t *testing.T) {
	t.Setenv("JWT_SECRET", "this-is-a-test-secret-key-at-least-32-characters")

	tokens, err := GenerateTokenPair(1, "user")
	if err != nil {
		t.Fatalf("Token generation failed: %v", err)
	}

	_, err = ValidateRefreshToken(tokens.AccessToken)

	if err == nil {
		t.Fatal("Expected access token to be rejected")
	}
}

func TestValidateInvalidRefreshToken(t *testing.T) {
	t.Setenv("JWT_SECRET", "this-is-a-test-secret-key-at-least-32-characters")

	_, err := ValidateRefreshToken("invalid-token")

	if err == nil {
		t.Fatal("Expected invalid token to be rejected")
	}
}
