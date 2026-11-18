package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func ConnectPostgres() (*sql.DB, error) {
	databaseURL := os.Getenv("DATABASE_URL")

	if databaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL environment variable is not set")
	}

	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("database connection failed: %w", err)
	}

	fmt.Println("PostgreSQL connected successfully!")

	return db, nil
}
