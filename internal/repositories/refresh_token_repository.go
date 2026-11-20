package repositories

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

type RefreshTokenRepository struct {
	DB *sql.DB
}

func NewRefreshTokenRepository(db *sql.DB) *RefreshTokenRepository {
	return &RefreshTokenRepository{
		DB: db,
	}
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (r *RefreshTokenRepository) SaveRefreshToken(
	ctx context.Context,
	userID int64,
	token string,
	expiresAt time.Time,
) error {

	query := `
        INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
        VALUES ($1, $2, $3)
    `

	_, err := r.DB.ExecContext(
		ctx,
		query,
		userID,
		hashToken(token),
		expiresAt,
	)

	return err
}

func (r *RefreshTokenRepository) ValidateRefreshToken(
	ctx context.Context,
	token string,
) (int64, error) {

	query := `
        SELECT user_id
        FROM refresh_tokens
        WHERE token_hash = $1
          AND revoked_at IS NULL
          AND expires_at > CURRENT_TIMESTAMP
    `

	var userID int64

	err := r.DB.QueryRowContext(
		ctx,
		query,
		hashToken(token),
	).Scan(&userID)

	if err != nil {
		return 0, errors.New("invalid or expired refresh token")
	}

	return userID, nil
}

func (r *RefreshTokenRepository) RevokeRefreshToken(
	ctx context.Context,
	token string,
) error {

	query := `
        UPDATE refresh_tokens
        SET revoked_at = CURRENT_TIMESTAMP
        WHERE token_hash = $1
          AND revoked_at IS NULL
    `

	result, err := r.DB.ExecContext(
		ctx,
		query,
		hashToken(token),
	)

	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return errors.New("refresh token not found or already revoked")
	}

	return nil
}
func (r *RefreshTokenRepository) RevokeAllUserRefreshTokens(
	ctx context.Context,
	userID int64,
) error {

	query := `
        UPDATE refresh_tokens
        SET revoked_at = CURRENT_TIMESTAMP
        WHERE user_id = $1
          AND revoked_at IS NULL
    `

	_, err := r.DB.ExecContext(ctx, query, userID)
	return err
}
func (r *RefreshTokenRepository) RotateRefreshToken(
	ctx context.Context,
	userID int64,
	oldToken string,
	newToken string,
	expiresAt time.Time,
) error {

	// 1. Start database transaction
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	// Rollback automatically if transaction is not committed
	defer tx.Rollback()

	// 2. Revoke the old refresh token
	updateQuery := `
		UPDATE refresh_tokens
		SET revoked_at = CURRENT_TIMESTAMP
		WHERE user_id = $1
		  AND token_hash = $2
		  AND revoked_at IS NULL
		  AND expires_at > CURRENT_TIMESTAMP
	`

	result, err := tx.ExecContext(
		ctx,
		updateQuery,
		userID,
		hashToken(oldToken),
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows != 1 {
		return errors.New("invalid or already revoked refresh token")
	}

	// 3. Save the new refresh token
	insertQuery := `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`

	_, err = tx.ExecContext(
		ctx,
		insertQuery,
		userID,
		hashToken(newToken),
		expiresAt,
	)
	if err != nil {
		return err
	}

	// 4. Commit transaction
	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}
