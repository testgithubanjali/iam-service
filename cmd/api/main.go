package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"iam-service/internal/database"
	"iam-service/internal/handlers"
	"iam-service/internal/middleware"
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

	// Disable trusted proxies for local development
	if err := router.SetTrustedProxies(nil); err != nil {
		log.Fatal(err)
	}

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "IAM Service is running",
		})
	})

	// Public authentication routes
	api := router.Group("/api/v1")
	auth := api.Group("/auth")

	auth.POST("/register", authHandler.Register)
	auth.POST("/login", authHandler.Login)
	auth.POST("/refresh", authHandler.Refresh)

	// Protected routes
	protected := api.Group("/")
	protected.Use(middleware.AuthMiddleware())

	protected.GET("/protected", func(c *gin.Context) {
		userID, _ := c.Get("userID")

		c.JSON(http.StatusOK, gin.H{
			"message": "You accessed a protected route!",
			"user_id": userID,
		})
	})

	protected.GET("/users/me", authHandler.GetMe)
	protected.PUT("/users/me", authHandler.UpdateProfile)
	protected.PUT("/users/change-password", authHandler.ChangePassword)
	for _, route := range router.Routes() {
		log.Printf("REGISTERED ROUTE: %s %s", route.Method, route.Path)
	}

	// Start server
	log.Println("IAM Server running on port 8080")

	if err := router.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
