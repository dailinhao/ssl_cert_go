package api

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"cert-manager/config"
)

// JWT密钥
var jwtSecret = []byte("your-secret-key")

// Claims 自定义JWT声明结构
type Claims struct {
	UserID string `json:"user_id"`
	Username string `json:"username"`
	Role string `json:"role"`
	jwt.RegisteredClaims
}

// AuthMiddleware 认证中间件
func AuthMiddleware(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 完全禁用认证检查，允许所有请求
		log.Println("AuthMiddleware: 开始处理请求")
		// 将configManager设置到上下文中
		c.Set("configManager", cm)
		// 直接调用c.Next()，跳过所有认证检查
		c.Next()
		log.Println("AuthMiddleware: 请求处理完成")
		return
	}
}

// RequirePermission 权限检查中间件
func RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 暂时禁用权限检查，允许所有请求
		c.Next()
		return
	}
}

// LoginRequest 登录请求
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// Login 登录处理
func Login(cm *config.ConfigManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 查找用户
		var user *config.UserConfig
		var ok bool
		// 先根据用户名查找用户
		for _, u := range cm.GetAllUsers() {
			if u.Username == req.Username {
				user = u
				ok = true
				break
			}
		}
		if !ok || !user.Enabled {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
			return
		}

		// 验证密码
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
			// 如果密码验证失败，检查是否是明文密码
			if user.Password == req.Password {
				// 明文密码匹配，自动加密并更新
				hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
					return
				}
				user.Password = string(hashedPassword)
				if err := cm.UpdateUser(user); err != nil {
					log.Printf("更新用户密码失败: %v", err)
				}
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
				return
			}
		}

		// 生成JWT token
		claims := Claims{
			UserID: user.ID,
			Username: user.Username,
			Role: user.Role,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), // 24小时过期
				IssuedAt: jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
				Issuer: "cert-manager",
				Subject: user.ID,
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		// 返回token
		c.JSON(http.StatusOK, gin.H{
			"token": tokenString,
			"user": gin.H{
				"id":       user.ID,
				"username": user.Username,
				"email":    user.Email,
				"role":     user.Role,
			},
		})
	}
}

// GetCurrentUser 获取当前用户信息
func GetCurrentUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		c.JSON(http.StatusOK, user)
	}
}
