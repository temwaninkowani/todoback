package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/api/idtoken"

	"github.com/go-sql-driver/mysql"
)

var db *sql.DB
var jwtKey = []byte("key")
var blacklist = make(map[string]bool)
var googleClientID = ""

type User struct {
	ID       int64  `json:"id"`
	User     string `json:"username"`
	Email    string `json:"email"`
	Pass     string `json:"password"`
	GoogleID string `json:"google_id"`
	AuthType string `json:"auth_type"`
}

type Task struct {
	ID          int64     `json:"id"`
	UID         int64     `json:"user_id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	TimeMade    time.Time `json:"created_at"`
	DueDate     time.Time `json:"dueDate"`
}

type SharedTask struct {
	ID          int64     `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	DueDate     time.Time `json:"dueDate"`
	UserEmails  []string  `json:"emails"`
}

type GoogleUser struct {
	Email         string `json:"email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	EmailVerified bool   `json:"email_verified"`
	Sub           string `json:"sub"`
}

func main() {

	cfg := mysql.Config{
		User:                 os.Getenv("DBUSER"),
		Passwd:               os.Getenv("DBPASS"),
		Net:                  "tcp",
		Addr:                 "127.0.0.1:3306",
		DBName:               "mytodolistuser",
		AllowNativePasswords: true,
		ParseTime:            true,
	}

	// initializes the db connection.
	var err error
	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatal(err)
	}

	//test connection
	pingErr := db.Ping()
	if pingErr != nil {
		log.Fatal(pingErr)
	}
	fmt.Println("Connected!")

	// Initialize Gin router.
	router := gin.Default()

	//enable cross orgin requests(CROS)
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	// User endpoints
	router.POST("/users", createUser)
	router.POST("/login", loginUser)
	router.GET("/user/:id", getUserByID)
	router.POST("/refresh", refreshToken)
	router.DELETE("/deleteUser/:id", removeUser) //should move this to authorized
	router.POST("/google", GoogleSignInHandler)
	router.POST("/logout", logoutHandler)

	// Protected task endpoints – grouped with authentication middleware.
	authorized := router.Group("/")
	authorized.Use(authMiddleware())
	{
		authorized.POST("/addTask/:id", createTask)
		authorized.GET("/tasks/:id", getTasksByID)
		authorized.POST("markOverdue/:id", markOverdue)
		authorized.POST("/markSharedOverdue/:id", markSharedOverdue)
		authorized.GET("/sharedTasks/:id", GetSharedTasks)
		authorized.POST("/createSharedTask/:id", CreateSharedTask)
		authorized.POST("/updateTask/:taskID", updateTaskStatus)
		authorized.POST("/updateSharedTask/:sharedTaskID", updateSharedTaskStatus)
		authorized.DELETE("/deleteTask/:taskID", deleteTask)
		authorized.DELETE("/deleteSharedTask/:sharedTaskID", deleteSharedTask)

	}

	router.Run("localhost:8081")

}

func generateToken(userID int64) (string, error) {
	// Create token with claims
	claims := jwt.MapClaims{
		"id":  userID,
		"exp": time.Now().Add(time.Hour * 24).Unix(), // Expires in 24 hours
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign and return the token
	return token.SignedString(jwtKey)

}

func generateRefreshToken(userID interface{}) (string, error) {
	claims := jwt.MapClaims{
		"id":  userID,
		"exp": time.Now().Add(7 * 24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// what even is hashing ??
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// compares a hashed password with a plain password on user login.
func verifyPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

//USER HANDLERS.

func getUserByID(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		log.Println("Invalid user ID:", c.Param("id"))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var user User
	err = db.QueryRow("SELECT id, username, email FROM users WHERE id = ?", userID).
		Scan(&user.ID, &user.User, &user.Email)

	if err != nil {
		if err == sql.ErrNoRows {
			log.Println("User not found for ID:", userID)
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		log.Println("Database error:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	log.Println("User found:", user)
	c.JSON(http.StatusOK, user)
}

func createUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Hash the password
	hashedPassword, err := hashPassword(user.Pass)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user.Pass = hashedPassword

	id, err := addUser(user)
	if err != nil {
		fmt.Println("failed to add user")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	user.ID = id
	user.Pass = ""
	c.JSON(http.StatusCreated, user)
}

func removeUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	rowsAffected, err := deleteUser(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User Not Found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user deleted Successfully"})

}

func loginUser(c *gin.Context) {

	var credentials struct {
		Email string `json:"email"`
		Pass  string `json:"password"`
	}
	if err := c.ShouldBindJSON(&credentials); err != nil {
		fmt.Println()
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := getUserByEmail(credentials.Email)
	if err != nil {
		fmt.Println("User not found")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	if !verifyPassword(user.Pass, credentials.Pass) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	token, err := generateToken(user.ID)
	if err != nil {
		fmt.Println("did not generate token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	refreshToken, err := generateRefreshToken(user.ID)
	if err != nil {
		fmt.Println("did not refresh token generate token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate refresh token"})
		return
	}

	c.SetCookie("auth_token", token, 3600*24, "/", "localhost", false, false)

	c.SetCookie("refresh_token", refreshToken, 3600*24*7, "/", "localhost", false, false)

	// Retrieve tasks for the user simultaneously(not really simultaneously , need to learn threads but for golang)
	tasks, err := fetchTasks(int(user.ID))
	if err != nil {
		fmt.Println("tasks not fetched")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user":  user,
		"tasks": tasks,
	})
}

func logoutHandler(c *gin.Context) {
	c.SetCookie("auth_token", "", -1, "/", "", false, true) // Expire the cookie
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func getUserByEmail(email string) (User, error) {
	var user User
	query := "SELECT id, username, email, password FROM users WHERE email = ?"
	err := db.QueryRow(query, email).Scan(&user.ID, &user.User, &user.Email, &user.Pass)
	if err != nil {
		if err == sql.ErrNoRows {
			return user, fmt.Errorf("getUserByEmail: no user found with email %s", email)
		}
		return user, fmt.Errorf("getUserByEmail: %v", err)
	}
	return user, nil
}

func addUser(user User) (int64, error) {
	result, err := db.Exec("INSERT INTO users (username, email , password ) VALUES (?,?,?)",
		user.User, user.Email, user.Pass,
	)
	if err != nil {
		fmt.Println("query failed")
		return 0, fmt.Errorf("addUser: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("addUser: %v", err)
	}
	return id, nil
}

func deleteUser(id int) (int64, error) {
	result, err := db.Exec("DELETE FROM users WHERE id = ? ", id)
	if err != nil {
		return 0, fmt.Errorf("deleteUser: %v", err)
	}
	RowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("deleteUser: %v", err)
	}
	return RowsAffected, nil

}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		// Get token from Authorization header
		tokenString := c.GetHeader("Authorization")

		// Check if token exists in cookie if not in header
		if tokenString == "" {
			tokenString, _ = c.Cookie("auth_token")
		} else if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:] // Strip "Bearer " prefix
		}

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
			c.Abort()
			return
		}

		// Check if token is blacklisted
		if _, blacklisted := blacklist[tokenString]; blacklisted {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is blacklisted"})
			c.Abort()
			return
		}

		// Validate the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		// Ensure "id" claim exists and convert it to string
		userIDFloat, ok := claims["id"].(float64)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
			c.Abort()
			return
		}

		userID := int(userIDFloat) // you have to convert float64 to int

		// Set user_id in the context
		c.Set("user_id", userID)
		c.Next()
	}
}

func refreshToken(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing refresh token"})
		return
	}

	// Validate the refresh token
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		return
	}

	userID := claims["id"].(float64)

	// Issue a new access token
	newAccessToken, err := generateToken(int64(userID))
	if err != nil {
		fmt.Println("failed to maek refresh token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate new token"})
		return
	}

	c.SetCookie("auth_token", newAccessToken, 3600*24, "/", "", false, false) // New JWT

	c.JSON(http.StatusOK, gin.H{"token": newAccessToken})
}

//TASK handlers:

func createTask(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var task Task

	// Bind JSON to struct (DueDate will be automatically parsed as time.Time)
	if err := c.ShouldBindJSON(&task); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// No need to parse task.DueDate again; it's already time.Time
	taskID, err := addTask(userID, task.Title, task.Description, task.DueDate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Respond with task ID and dueDate in RFC3339 format
	c.JSON(http.StatusCreated, gin.H{
		"task_id": taskID,
		"dueDate": task.DueDate.Format(time.RFC3339),
	})
}

func getTasksByID(c *gin.Context) {
	// Get userID from URL parameter
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Fetch tasks for the user
	tasks, err := fetchTasks(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve tasks"})
		return
	}

	c.JSON(http.StatusOK, tasks)
}

func fetchTasks(userID int) ([]Task, error) {
	rows, err := db.Query("SELECT id, user_id, title, description, status, dueDate FROM tasks WHERE user_id = ?", userID)
	if err != nil {
		return nil, fmt.Errorf("fetchTasks: %v", err)
	}
	defer rows.Close()

	var tasks []Task
	for rows.Next() {
		var task Task
		// Scan into the task struct, including dueDate as time.Time
		if err := rows.Scan(&task.ID, &task.UID, &task.Title, &task.Description, &task.Status, &task.DueDate); err != nil {
			return nil, fmt.Errorf("fetchTasks: failed to scan row: %v", err)
		}

		tasks = append(tasks, task)
	}

	if len(tasks) == 0 {
		return []Task{}, nil
	}

	return tasks, nil
}

func addTask(userID int, title string, description string, dueDate time.Time) (int64, error) {
	result, err := db.Exec("INSERT INTO tasks (user_id, title, description, dueDate) VALUES (?, ?, ?, ?)",
		userID, title, description, dueDate.Format(time.RFC3339),
	)

	if err != nil {
		return 0, fmt.Errorf("addTask: %v", err)
	}

	taskID, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("addTask: failed to retrieve last insert ID: %v", err)
	}

	return taskID, nil
}

func updateTaskStatus(c *gin.Context) {
	taskID := c.Param("taskID")
	var task Task
	if err := c.ShouldBindJSON(&task); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err := db.Exec("UPDATE tasks SET status = ? WHERE id = ?", task.Status, taskID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update task"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Task updated successfully"})
}

func deleteTask(c *gin.Context) {
	taskID, err := strconv.Atoi(c.Param("taskID"))

	if err != nil {
		fmt.Println("Error converting taskID:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "wrong task id"})
		return
	}

	rowsAffected, err := removeTask(taskID)
	if err != nil {
		fmt.Println("Error deleting task:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if rowsAffected == 0 {
		fmt.Println("Task not found in DB")
		c.JSON(http.StatusNotFound, gin.H{"error": "Task Not Found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Task deleted successfully"})
}

func removeTask(id int) (int64, error) {

	result, err := db.Exec("DELETE FROM tasks WHERE id = ?", id)
	if err != nil {
		fmt.Println("SQL delete error:", err)
		return 0, fmt.Errorf("deleteUser: %v", err)
	}
	RowsAffected, err := result.RowsAffected()
	if err != nil {
		fmt.Println("Error fetching rows affected:", err)
		return 0, fmt.Errorf("deleteUser: %v", err)
	}
	return RowsAffected, nil
}

// stuff for marking overdue tasks both shared and personal.

func markUserOverdueTasks(userID int64) error {
	_, err := db.Exec("UPDATE tasks SET status = 'overdue' WHERE user_id = ? AND dueDate IS NOT NULL AND dueDate < CURDATE() AND status != 'completed'", userID)
	return err
}

func markSharedTasksOverdue(userID int64) error {
	_, err := db.Exec("UPDATE shared_tasks SET status = 'overdue' WHERE admin_id = ? AND dueDate IS NOT NULL AND dueDate < CURDATE() AND status != 'completed'", userID)
	return err
}

func markSharedOverdue(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	err = markSharedTasksOverdue(int64(userID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mark tasks as overdue"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "shared User tasks marked as overdue"})
}

func markOverdue(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	err = markUserOverdueTasks(int64(userID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mark tasks as overdue"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User tasks marked as overdue"})
}

//SHARED TASK HANDLERS:

func GetUserIDsByEmails(emails []string) ([]int, error) {
	var userIDs []int

	// Handle empty emails case
	if len(emails) == 0 {
		return nil, fmt.Errorf("getUserIDsByEmails: no emails provided")
	}

	// Convert email list into query placeholders (?,?,? for SQL IN clause)
	placeholders := strings.Repeat("?,", len(emails))
	placeholders = placeholders[:len(placeholders)-1]

	query := fmt.Sprintf("SELECT id FROM users WHERE email IN (%s)", placeholders)

	// Convert []string to []interface{} for query arguments
	args := make([]interface{}, len(emails))
	for i, email := range emails {
		args[i] = email
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("getUserIDsByEmails: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var userID int
		if err := rows.Scan(&userID); err != nil {
			return nil, fmt.Errorf("getUserIDsByEmails: failed to scan user ID: %v", err)
		}
		userIDs = append(userIDs, userID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("getUserIDsByEmails: %v", err)
	}

	return userIDs, nil
}

func CreateSharedTask(c *gin.Context) {
	adminID, err := strconv.Atoi(c.Param("id"))

	if err != nil {
		fmt.Printf("failed to get user id")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	creator, err := GetUserEmailByID(adminID)
	if err != nil {
		fmt.Println("failed to get email from id")
	}
	var shared SharedTask

	if err := c.ShouldBindJSON(&shared); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userIDs, err := GetUserIDsByEmails(shared.UserEmails)
	if err != nil {
		fmt.Printf("get emails by ID failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	sharedTaskID, err := AddSharedTask(adminID, shared.Title, shared.Description, shared.DueDate, userIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Send emails to the users
	for _, userEmail := range shared.UserEmails {
		subject := "Task Assigned: " + shared.Title
		body := fmt.Sprintf("Dear %s, you have been assigned a task by %s. \nTitle: %s \nDescription: %s \nTo be completed by: %s.",
			userEmail, creator, shared.Title, shared.Description, shared.DueDate.Format("2006-01-02 15:04:05"))

		err := sendEmail(userEmail, subject, body)

		if err != nil {
			fmt.Printf("failed to send email to %s: %v\n", userEmail, err)
		}
	}

	c.JSON(http.StatusCreated, gin.H{"shared_task_id": sharedTaskID})
}

func AddSharedTask(adminID int, title string, description string, dueDate time.Time, userIDs []int) (int64, error) {
	var result sql.Result
	var err error

	// Insert task into shared_tasks table
	result, err = db.Exec("INSERT INTO shared_tasks (admin_id, title, description, dueDate) VALUES (?, ?, ?, ?)",
		adminID, title, description, dueDate,
	)
	if err != nil {
		return 0, fmt.Errorf("addSharedTask: %v", err)
	}

	// Retrieve task ID
	sharedTaskID, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("addSharedTask: failed to retrieve last insert ID: %v", err)
	}

	for _, userID := range userIDs {
		_, err := db.Exec("INSERT INTO shared_task_users (shared_task_id, user_id) VALUES (?, ?)", sharedTaskID, userID)
		if err != nil {
			return 0, fmt.Errorf("addSharedTask: failed to assign user %d: %v", userID, err)
		}
	}

	_, err = db.Exec("INSERT INTO shared_task_users (shared_task_id, user_id) VALUES (?, ?)", sharedTaskID, adminID)
	if err != nil {
		return 0, fmt.Errorf("addSharedTask: failed to assign admin %d: %v", adminID, err)
	}

	return sharedTaskID, nil
}

func GetSharedTasks(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	rows, err := db.Query(`
        SELECT st.id, st.title, st.description, st.status, st.dueDate
        FROM shared_tasks st
        JOIN shared_task_users stu ON st.id = stu.shared_task_id
        WHERE stu.user_id = ?
        ORDER BY st.id
    `, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve shared tasks"})
		return
	}
	defer rows.Close()

	var tasks []SharedTask

	for rows.Next() {
		var task SharedTask
		if err := rows.Scan(
			&task.ID,
			&task.Title,
			&task.Description,
			&task.Status,
			&task.DueDate,
		); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error scanning tasks"})
			return
		}

		tasks = append(tasks, task)
	}

	c.JSON(http.StatusOK, tasks)
}

func GetUserEmailByID(userID int) (string, error) {
	var email string
	err := db.QueryRow("SELECT email FROM users WHERE id = ?", userID).Scan(&email)
	if err != nil {
		return "", fmt.Errorf("getUserEmailByID: %v", err)
	}
	return email, nil
}

func updateSharedTaskStatus(c *gin.Context) {
	SharedTaskID := c.Param("sharedTaskID")

	var shared SharedTask
	if err := c.ShouldBindJSON(&shared); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return

	}

	_, err := db.Exec("UPDATE shared_tasks SET status=? WHERE id = ?", shared.Status, SharedTaskID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update task status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "task status updated successfully"})

}

func deleteSharedTask(c *gin.Context) {
	sharedTaskID, err := strconv.Atoi(c.Param("sharedTaskID"))
	if err != nil {
		fmt.Println("Error converting sharedTaskID:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "wrong task id"})
		return
	}

	rowsAffected, err := removeSHaredTask(sharedTaskID)
	if err != nil {
		fmt.Println("couldnt delete shared task", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if rowsAffected == 0 {
		fmt.Println(" shared Task not found in DB")
		c.JSON(http.StatusNotFound, gin.H{"error": " sharedTask Not Found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": " shared Task deleted successfully"})

}

func removeSHaredTask(id int) (int64, error) {

	result, err := db.Exec("DELETE FROM shared_tasks WHERE id = ?", id)
	if err != nil {
		fmt.Println("SQL delete error:", err)
		return 0, fmt.Errorf("deleteUser: %v", err)
	}
	RowsAffected, err := result.RowsAffected()
	if err != nil {
		fmt.Println("Error fetching rows affected:", err)
		return 0, fmt.Errorf("deleteUser: %v", err)
	}
	return RowsAffected, nil
}

//GOOGLE SIGNIN HANDLERS

// might be buggy(efinetlt buggy!)
func verifyGoogleToken(token string) (*GoogleUser, error) {
	payload, err := idtoken.Validate(context.Background(), token, googleClientID)
	if err != nil {
		return nil, errors.New("invalid Google token on verification")
	}

	log.Printf("Token payload: %+v\n", payload)

	// Ensure the token was issued for your client ID
	if payload.Audience != googleClientID {
		return nil, errors.New("token audience mismatch")
	}

	googleUser := &GoogleUser{}

	// Extract required fields safely
	if email, ok := payload.Claims["email"].(string); ok {
		googleUser.Email = email
	} else {
		return nil, errors.New("email claim is missing or not a string")
	}

	if name, ok := payload.Claims["name"].(string); ok {
		googleUser.Name = name
	} else {
		return nil, errors.New("name claim is missing or not a string")
	}

	if picture, ok := payload.Claims["picture"].(string); ok {
		googleUser.Picture = picture
	} else {
		return nil, errors.New("picture claim is missing or not a string")
	}

	if emailVerified, ok := payload.Claims["email_verified"].(bool); ok {
		googleUser.EmailVerified = emailVerified
	} else {
		return nil, errors.New("email_verified claim is missing or not a boolean")
	}

	if sub, ok := payload.Claims["sub"].(string); ok {
		googleUser.Sub = sub
	} else {
		return nil, errors.New("sub claim is missing or not a string")
	}

	return googleUser, nil
}

func GoogleSignInHandler(c *gin.Context) {
	var req struct {
		Token string `json:"token"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	//fmt.Println(req.Token)

	googleUser, err := verifyGoogleToken(req.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Google token on sign in"})
		return
	}

	email := googleUser.Email
	googleID := googleUser.Sub

	// Check if a user already exists
	var user User
	err = db.QueryRow("SELECT id, email, google_id, auth_type FROM users WHERE email = ?", email).
		Scan(&user.ID, &user.Email, &user.GoogleID, &user.AuthType)

	if err == sql.ErrNoRows {
		// User does not exist create one
		userID, err := createGoogleUser(email, googleID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create Google user"})
			return
		}

		user = User{
			ID:       userID,
			Email:    email,
			GoogleID: googleID,
			AuthType: "google",
		}
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	} else {

		//update details for an existing user to google.
		if user.AuthType == "password" && user.GoogleID == "" {
			if err := newGoogleUser(user.ID, googleID); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update user to Google auth"})
				return
			}
			user.GoogleID = googleID
			user.AuthType = "google"
		}
	}

	token, err := generateToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"token":   token,
	})
}

func createGoogleUser(email string, googleID string) (int64, error) {
	query := "INSERT INTO users (email, google_id, auth_type) VALUES (?, ?, 'google')"
	result, err := db.Exec(query, email, googleID)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func newGoogleUser(userID int64, googleID string) error {
	_, err := db.Exec("UPDATE users SET google_id = ?, auth_type = 'google' WHERE id = ?", googleID, userID)
	return err

}

//email handler

// Send an email using Gmail SMTP
func sendEmail(to, subject, body string) error {
	from := "temwaninkowani@gmail.com"
	password := "gnvattjwhrvttogh"
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	// Set up authentication
	auth := smtp.PlainAuth("", from, password, smtpHost)

	// Create the email message
	msg := []byte("To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" + body)

	// Send the email
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, msg)
	return err
}
