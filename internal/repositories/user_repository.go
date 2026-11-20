package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"iam-service/internal/models"
)

type UserRepository struct {
	DB *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{
		DB: db,
	}
}

func (r *UserRepository) Create(
	ctx context.Context,
	name string,
	email string,
	passwordHash string,
) (*models.User, error) {

	query := `
                INSERT INTO users (name, email, password_hash)
                VALUES ($1, $2, $3)
                RETURNING id, name, email, created_at
        `

	user := &models.User{}

	err := r.DB.QueryRowContext(
		ctx,
		query,
		name,
		email,
		passwordHash,
	).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

func (r *UserRepository) FindByEmail(
	ctx context.Context,
	email string,
) (*models.User, string, error) {

	query := `
        SELECT id, name, email, password_hash, created_at
        FROM users
        WHERE email = $1
    `

	user := &models.User{}
	var passwordHash string

	err := r.DB.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&passwordHash,
		&user.CreatedAt,
	)

	if err != nil {
		return nil, "", err
	}

	return user, passwordHash, nil
}

func (r *UserRepository) GetByID(
	ctx context.Context,
	id int64,
) (*models.User, error) {

	query := `
		SELECT id, name, email, created_at
		FROM users
		WHERE id = $1
	`

	user := &models.User{}

	err := r.DB.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}
func (r *UserRepository) UpdateProfile(
	ctx context.Context,
	userID int64,
	name string,
	email string,
) (*models.User, error) {

	query := `
        UPDATE users
        SET name = $1,
            email = $2,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $3
        RETURNING id, name, email, created_at
    `

	var user models.User

	err := r.DB.QueryRowContext(
		ctx,
		query,
		name,
		email,
		userID,
	).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to update user profile: %w", err)
	}

	return &user, nil
}
func (r *UserRepository) UpdatePassword(
	ctx context.Context,
	userID int64,
	passwordHash string,
) error {

	query := `
        UPDATE users
        SET password_hash = $1,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $2
    `

	result, err := r.DB.ExecContext(
		ctx,
		query,
		passwordHash,
		userID,
	)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return errors.New("user not found")
	}

	return nil
}
func (r *UserRepository) FindByUserID(
	ctx context.Context,
	userID int64,
) (*models.User, string, error) {

	query := `
        SELECT id, name, email, password_hash, created_at
        FROM users
        WHERE id = $1
    `

	var user models.User
	var passwordHash string

	err := r.DB.QueryRowContext(
		ctx,
		query,
		userID,
	).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&passwordHash,
		&user.CreatedAt,
	)

	if err != nil {
		return nil, "", err
	}

	return &user, passwordHash, nil
}
func (r *UserRepository) UpdatePasswordAndRevokeTokens(
	ctx context.Context,
	userID int64,
	passwordHash string,
) error {

	// 1. Start database transaction
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer tx.Rollback()

	// 2. Update user password
	updatePasswordQuery := `
        UPDATE users
        SET password_hash = $1,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $2
    `

	result, err := tx.ExecContext(
		ctx,
		updatePasswordQuery,
		passwordHash,
		userID,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return errors.New("user not found")
	}

	// 3. Revoke all active refresh tokens
	revokeTokensQuery := `
        UPDATE refresh_tokens
        SET revoked_at = CURRENT_TIMESTAMP
        WHERE user_id = $1
          AND revoked_at IS NULL
    `

	_, err = tx.ExecContext(
		ctx,
		revokeTokensQuery,
		userID,
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
