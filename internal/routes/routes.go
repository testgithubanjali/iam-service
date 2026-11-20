package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"iam-service/internal/handlers"
	adminhandler "iam-service/internal/handlers/admin"
	"iam-service/internal/middleware"
)

func SetupRouter(
	authHandler *handlers.AuthHandler,
	adminHandler *adminhandler.AdminHandler,
) *gin.Engine {
	// Create Gin router
	router := gin.Default()

	// Disable trusted proxies for local development
	_ = router.SetTrustedProxies(nil)

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "IAM Service is running",
		})
	})

	// API version group
	api := router.Group("/api/v1")

	// =================================
	// PUBLIC AUTHENTICATION ROUTES
	// =================================

	auth := api.Group("/auth")

	auth.POST("/register", authHandler.Register)
	auth.POST("/login", authHandler.Login)
	auth.POST("/refresh", authHandler.Refresh)
	auth.POST("/logout", authHandler.Logout)

	// =================================
	// PROTECTED USER ROUTES
	// =================================

	protected := api.Group("/")
	protected.Use(middleware.AuthMiddleware())

	// Protected test route
	protected.GET("/protected", func(c *gin.Context) {
		userID, _ := c.Get("userID")
		userRole, _ := c.Get("userRole")

		c.JSON(http.StatusOK, gin.H{
			"message":   "You accessed a protected route!",
			"user_id":   userID,
			"user_role": userRole,
		})
	})

	// User profile routes
	users := protected.Group("/users")

	users.GET("/me", authHandler.GetMe)
	users.PUT("/me", authHandler.UpdateProfile)
	users.PUT("/change-password", authHandler.ChangePassword)

	// =================================
	// ADMIN ROUTES
	// =================================

	admin := api.Group("/admin")
	admin.Use(
		middleware.AuthMiddleware(),
		middleware.AdminOnly(),
	)

	// Admin test route
	admin.GET("/dashboard", func(c *gin.Context) {
		userID, _ := c.Get("userID")

		c.JSON(http.StatusOK, gin.H{
			"message": "Welcome to the admin dashboard",
			"user_id": userID,
			"role":    "admin",
		})
	})
	admin.GET("/users", adminHandler.GetAllUsers)
	admin.GET("/users/:id", adminHandler.GetUserByID)
	admin.PUT("/users/:id/role", adminHandler.UpdateUserRole)
	admin.DELETE("/users/:id", adminHandler.DeleteUser)

	return router
}
