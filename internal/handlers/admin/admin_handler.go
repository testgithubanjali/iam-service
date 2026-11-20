package admin

import (
	"database/sql"
	"errors"
	"github.com/gin-gonic/gin"
	"iam-service/internal/repositories"
	"net/http"
	"strconv"
)

type AdminHandler struct {
	UserRepo *repositories.UserRepository
}

func NewAdminHandler(userRepo *repositories.UserRepository) *AdminHandler {
	return &AdminHandler{
		UserRepo: userRepo,
	}
}

func (h *AdminHandler) GetAllUsers(c *gin.Context) {
	users, err := h.UserRepo.GetAllUsers(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to fetch users",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
	})
}
func (h *AdminHandler) GetUserByID(c *gin.Context) {
	id := c.Param("id")

	userID, err := strconv.ParseInt(id, 10, 64)
	if err != nil || userID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	user, err := h.UserRepo.GetByID(c.Request.Context(), userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to fetch user",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": user,
	})
}
func (h *AdminHandler) UpdateUserRole(c *gin.Context) {
	id := c.Param("id")

	userID, err := strconv.ParseInt(id, 10, 64)
	if err != nil || userID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	var request struct {
		Role string `json:"role"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
		})
		return
	}

	if request.Role != "user" && request.Role != "admin" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Role must be either user or admin",
		})
		return
	}

	user, err := h.UserRepo.UpdateUserRole(
		c.Request.Context(),
		userID,
		request.Role,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update user role",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User role updated successfully",
		"user":    user,
	})
}
