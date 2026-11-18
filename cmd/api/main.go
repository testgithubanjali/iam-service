package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"iam-service/internal/database"
	"iam-service/internal/handlers"
	"iam-service/internal/repositories"
	"iam-service/internal/services"
)

func main() {
	// Connect to PostgreSQL
	db, err := database.ConnectPostgres()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Initialize application layers
	userRepo := repositories.NewUserRepository(db)
	authService := services.NewAuthService(userRepo)
	authHandler := handlers.NewAuthHandler(authService)

	// Create Gin router
	router := gin.Default()

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "IAM Service is running",
		})
	})

	// Authentication routes
	api := router.Group("/api/v1")
	auth := api.Group("/auth")

	auth.POST("/register", authHandler.Register)

	// Start server
	log.Println("IAM Server running on port 8080")

	if err := router.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
