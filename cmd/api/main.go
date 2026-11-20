package main

import (
	"log"

	"iam-service/internal/database"
	"iam-service/internal/handlers"
	"iam-service/internal/repositories"
	"iam-service/internal/routes"
	"iam-service/internal/services"
)

func main() {

	// 1. Connect to PostgreSQL
	db, err := database.ConnectPostgres()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// 2. Initialize repositories
	userRepo := repositories.NewUserRepository(db)
	refreshTokenRepo := repositories.NewRefreshTokenRepository(db)

	// 3. Initialize services
	authService := services.NewAuthService(
		userRepo,
		refreshTokenRepo,
	)

	// 4. Initialize handlers
	authHandler := handlers.NewAuthHandler(authService)

	// 5. Initialize routes
	router := routes.SetupRouter(authHandler)

	// 6. Print registered routes
	for _, route := range router.Routes() {
		log.Printf("REGISTERED ROUTE: %s %s", route.Method, route.Path)
	}

	// 7. Start server
	log.Println("IAM Server running on port 8080")

	if err := router.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
