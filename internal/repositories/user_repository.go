package repositories

import (
	"context"
	"database/sql"
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
