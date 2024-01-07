package main

import (
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"golang.org/x/crypto/bcrypt"
	 _ "github.com/mattn/go-sqlite3"

)

var (
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	secretKey = []byte("")
)

type User struct {
	ID        uint      `json:"id" gorm:"primary_key"`
	Username  string    `json:"username" gorm:"unique;not null"`
	Email     string    `json:"email" gorm:"unique;not null"`
	Password  string    `json:"-" gorm:"not null"`
	Posts     []Post    `json:"posts,omitempty" gorm:"foreignkey:UserID"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Post struct {
	ID        uint      `json:"id" gorm:"primary_key"`
	Title     string    `json:"title" binding:"required"`
	Content   string    `json:"content" binding:"required"`
	UserID    uint      `json:"user_id"`
	User      User      `json:"user,omitempty" gorm:"foreignkey:UserID"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type WebSocketMessage struct {
	Event string      `json:"event"`
	Data  interface{} `json:"data"`
}

type JWTClaims struct {
	UserID uint `json:"user_id"`
	jwt.StandardClaims
}

func main() {
	router := gin.Default()
	router.Use(cors.Default())

	db, err := gorm.Open("sqlite3", "test.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db.AutoMigrate(&User{}, &Post{})

	router.GET("/ws", func(c *gin.Context) {
		serveWebSocket(c.Writer, c.Request, db)
	})

	authGroup := router.Group("/auth")
	{
		authGroup.POST("/register", RegisterHandler(db))
		authGroup.POST("/login", LoginHandler(db))
	}
	apiGroup := router.Group("/api")
	apiGroup.Use(AuthMiddleware())

	{
		apiGroup.POST("/posts", CreatePostHandler(db))
		apiGroup.GET("/posts", GetPostsHandler(db))
	}

	router.Run(":8080")
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
			return secretKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(*JWTClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		c.Set("claims", claims)
		c.Next()
	}
}

func RegisterHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var user User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
			return
		}

		user.Password = string(hashedPassword)

		if err := db.Create(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
	}
}

func LoginHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var loginData struct {
			UsernameOrEmail string `json:"username_or_email" binding:"required"`
			Password        string `json:"password" binding:"required"`
		}

		if err := c.ShouldBindJSON(&loginData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}

		var user User
		if err := db.Where("username = ? OR email = ?", loginData.UsernameOrEmail, loginData.UsernameOrEmail).First(&user).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		token := generateToken(user.ID)
		c.JSON(http.StatusOK, gin.H{"token": token})
	}
}

func CreatePostHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var post Post
		if err := c.ShouldBindJSON(&post); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}

		claims := c.MustGet("claims").(*JWTClaims)
		post.UserID = claims.UserID

		if err := db.Create(&post).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
			return
		}

		message := WebSocketMessage{
			Event: "new_post",
			Data:  post,
		}
		BroadcastMessage(message)

		c.JSON(http.StatusCreated, post)
	}
}

func GetPostsHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var posts []Post
		db.Preload("User").Find(&posts)
		c.JSON(http.StatusOK, posts)
	}
}

func generateToken(userID uint) string {
	claims := JWTClaims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // 24 hours
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(secretKey)
	return tokenString
}

func serveWebSocket(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			log.Println(err)
			return
		}
	}
}

func BroadcastMessage(message WebSocketMessage) {
	for client := range connectedClients {
		err := client.WriteJSON(message)
		if err != nil {
			log.Println(err)
			client.Close()
			delete(connectedClients, client)
		}
	}
}

var connectedClients = make(map[*websocket.Conn]bool)
