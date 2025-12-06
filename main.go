package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var db *gorm.DB
var JwtSecretKey = []byte("SECRET_KEY")

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"unique;not null"`
	Password string `gorm:"not null"`
	IsAdmin  bool   `gorm:"default:false"`
	Carts    []Cart
}

type Product struct {
	ID    uint    `gorm:"primaryKey"`
	Title string  `gorm:"not null"`
	Price float64 `gorm:"not null"`
	Stock int     `gorm:"default:0"`
}

type Cart struct {
	ID         uint `gorm:"primaryKey"`
	UserID     uint `gorm:"index"`
	Items      []CartItem
	CheckedOut bool `gorm:"default:false"`
	CreatedAt  time.Time
}

type CartItem struct {
	ID        uint `gorm:"primaryKey"`
	CartID    uint
	ProductID uint
	Product   Product
	Quantity  int `gorm:"default:1"`
	UnitPrice float64
}

type Payment struct {
	ID         uint `gorm:"primaryKey"`
	CartID     uint
	Amount     float64
	Provider   string
	ProviderID string
	CreatedAt  time.Time
}

// Card represents a very simple stored card for demo payment validation.
type Card struct {
	ID         uint   `gorm:"primaryKey"`
	Number     string `gorm:"unique;not null"`
	HolderName string `gorm:"not null"`
	ExpMonth   int    `gorm:"not null"`
	ExpYear    int    `gorm:"not null"`
	CVV        string `gorm:"not null"`
}

// ShopPage renders the public products page (no auth required).
func ShopPage(c *gin.Context) {
	c.HTML(http.StatusOK, "shop.html", nil)
}

// CartPage renders the cart page.
func CartPage(c *gin.Context) {
	c.HTML(http.StatusOK, "cart.html", nil)
}

// PayPage renders the payment page.
func PayPage(c *gin.Context) {
	c.HTML(http.StatusOK, "pay.html", nil)
}

// ProductsPage renders the admin-only products management page.
func ProductsPage(c *gin.Context) {
	c.HTML(http.StatusOK, "products.html", nil)
}

// AddProductPage renders the add product page.
func AddProductPage(c *gin.Context) {
	c.HTML(http.StatusOK, "add_product.html", nil)
}

// UpdateProductPage renders the update product page.
func UpdateProductPage(c *gin.Context) {
	c.HTML(http.StatusOK, "update_product.html", nil)
}

// GetProducts returns all products as JSON (public endpoint for shop).
func GetProducts(c *gin.Context) {
	var products []Product
	if err := db.Find(&products).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch products"})
		return
	}
	c.JSON(http.StatusOK, products)
}

// VerifyAdminToken verifies if a JWT token belongs to an admin user.
func VerifyAdminToken(c *gin.Context) {
	var input struct {
		Token string `json:"token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token is required"})
		return
	}

	token, err := jwt.Parse(input.Token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return JwtSecretKey, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token", "is_admin": false})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims", "is_admin": false})
		return
	}

	isAdmin, ok := claims["is_admin"].(bool)
	if !ok || !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required", "is_admin": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "Token verified",
		"is_admin": true,
		"username": claims["username"],
	})
}

// AdminGetProducts returns all products for admin (requires admin token).
func AdminGetProducts(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid Authorization header"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return JwtSecretKey, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		return
	}

	isAdmin, ok := claims["is_admin"].(bool)
	if !ok || !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	var products []Product
	if err := db.Find(&products).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch products"})
		return
	}
	c.JSON(http.StatusOK, products)
}

// AdminGetProduct returns a single product by ID for admin (requires admin token).
func AdminGetProduct(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid Authorization header"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return JwtSecretKey, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		return
	}

	isAdmin, ok := claims["is_admin"].(bool)
	if !ok || !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	productID := c.Param("id")
	var product Product
	if err := db.First(&product, productID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}

	c.JSON(http.StatusOK, product)
}

// AdminAddProduct allows admin users to create a new product via JSON body.
func AdminAddProduct(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid Authorization header"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return JwtSecretKey, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		return
	}

	isAdmin, ok := claims["is_admin"].(bool)
	if !ok || !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	var input struct {
		Title string  `json:"title" binding:"required"`
		Price float64 `json:"price" binding:"required"`
		Stock int     `json:"stock" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid product data"})
		return
	}

	product := Product{
		Title: input.Title,
		Price: input.Price,
		Stock: input.Stock,
	}
	if err := db.Create(&product).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create product"})
		return
	}

	c.JSON(http.StatusOK, product)
}

// AdminUpdateProduct allows admin users to update a product.
func AdminUpdateProduct(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid Authorization header"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return JwtSecretKey, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		return
	}

	isAdmin, ok := claims["is_admin"].(bool)
	if !ok || !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	productID := c.Param("id")
	var product Product
	if err := db.First(&product, productID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}

	var input struct {
		Title string  `json:"title"`
		Price float64 `json:"price"`
		Stock int     `json:"stock"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid product data"})
		return
	}

	if input.Title != "" {
		product.Title = input.Title
	}
	if input.Price > 0 {
		product.Price = input.Price
	}
	if input.Stock >= 0 {
		product.Stock = input.Stock
	}

	if err := db.Save(&product).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update product"})
		return
	}

	c.JSON(http.StatusOK, product)
}

// AdminDeleteProduct allows admin users to delete a product.
func AdminDeleteProduct(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid Authorization header"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return JwtSecretKey, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		return
	}

	isAdmin, ok := claims["is_admin"].(bool)
	if !ok || !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	productID := c.Param("id")
	var product Product
	if err := db.First(&product, productID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}

	if err := db.Delete(&product).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete product"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Product deleted successfully"})
}

func SignUpPage(c *gin.Context) {
	c.HTML(http.StatusOK, "signup.html", nil)
}

func SignUp(c *gin.Context) {
	type SignUpRequest struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
		IsAdmin  bool   `json:"is_admin"`
	}

	var req SignUpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid form data"})
		return
	}

	hashedPw, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	user := User{Username: req.Username, Password: string(hashedPw), IsAdmin: req.IsAdmin}

	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"is_admin": user.IsAdmin,
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
	})

	tokenString, _ := token.SignedString(JwtSecretKey)

	c.JSON(http.StatusOK, gin.H{
		"message": "User created successfully",
		"token":   tokenString,
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"is_admin": user.IsAdmin,
		},
	})
}

// GetCart returns the current user's cart with all items.
func GetCart(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required. Please sign in."})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return JwtSecretKey, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token. Please sign in again."})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		return
	}

	userID, ok := claims["user_id"].(float64)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID in token"})
		return
	}

	// Find active cart for user
	var cart Cart
	if err := db.Where("user_id = ? AND checked_out = ?", uint(userID), false).Preload("Items.Product").First(&cart).Error; err != nil {
		// No active cart, return empty cart
		c.JSON(http.StatusOK, gin.H{
			"cart":  nil,
			"total": 0.0,
		})
		return
	}

	// Calculate total
	var total float64
	for _, item := range cart.Items {
		total += float64(item.Quantity) * item.UnitPrice
	}

	c.JSON(http.StatusOK, gin.H{
		"cart":  cart,
		"total": total,
	})
}

// AddToCart allows authenticated users to add a product to their cart.
func AddToCart(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required. Please sign in."})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return JwtSecretKey, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token. Please sign in again."})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		return
	}

	userID, ok := claims["user_id"].(float64)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID in token"})
		return
	}

	var input struct {
		ProductID uint `json:"product_id" binding:"required"`
		Quantity  int  `json:"quantity"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	if input.Quantity <= 0 {
		input.Quantity = 1
	}

	// Check if product exists and has stock
	var product Product
	if err := db.First(&product, input.ProductID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}

	if product.Stock < input.Quantity {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Insufficient stock available"})
		return
	}

	// Find or create active cart for user
	var cart Cart
	if err := db.Where("user_id = ? AND checked_out = ?", uint(userID), false).First(&cart).Error; err != nil {
		// Create new cart
		cart = Cart{
			UserID:     uint(userID),
			CheckedOut: false,
			CreatedAt:  time.Now(),
		}
		if err := db.Create(&cart).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create cart"})
			return
		}
	}

	// Check if product already in cart
	var cartItem CartItem
	if err := db.Where("cart_id = ? AND product_id = ?", cart.ID, input.ProductID).First(&cartItem).Error; err == nil {
		// Update quantity
		newQuantity := cartItem.Quantity + input.Quantity
		if product.Stock < newQuantity {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Insufficient stock available"})
			return
		}
		cartItem.Quantity = newQuantity
		if err := db.Save(&cartItem).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update cart item"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Cart updated successfully", "cart_item": cartItem})
		return
	}

	// Create new cart item
	cartItem = CartItem{
		CartID:    cart.ID,
		ProductID: input.ProductID,
		Quantity:  input.Quantity,
		UnitPrice: product.Price,
	}
	if err := db.Create(&cartItem).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add item to cart"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Product added to cart successfully", "cart_item": cartItem})
}

// RemoveFromCart allows authenticated users to remove a product from their cart.
func RemoveFromCart(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required. Please sign in."})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return JwtSecretKey, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token. Please sign in again."})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		return
	}

	userID, ok := claims["user_id"].(float64)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID in token"})
		return
	}

	// Get cart item ID from URL parameter
	cartItemID := c.Param("id")
	if cartItemID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cart item ID is required"})
		return
	}

	// Find active cart for user
	var cart Cart
	if err := db.Where("user_id = ? AND checked_out = ?", uint(userID), false).First(&cart).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No active cart found"})
		return
	}

	// Find and verify the cart item belongs to user's cart
	var cartItem CartItem
	if err := db.Where("id = ? AND cart_id = ?", cartItemID, cart.ID).First(&cartItem).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Cart item not found"})
		return
	}

	// Delete the cart item
	if err := db.Delete(&cartItem).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove item from cart"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Item removed from cart successfully"})
}

// ProcessPayment validates card details and processes the payment.
func ProcessPayment(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required. Please sign in."})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return JwtSecretKey, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token. Please sign in again."})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		return
	}

	userID, ok := claims["user_id"].(float64)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID in token"})
		return
	}

	var input struct {
		HolderName string `json:"holder_name" binding:"required"`
		CardNumber string `json:"card_number" binding:"required"`
		ExpMonth   int    `json:"exp_month" binding:"required"`
		ExpYear    int    `json:"exp_year" binding:"required"`
		CVV        string `json:"cvv" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payment data"})
		return
	}

	// Clean card number (remove spaces)
	cardNumber := strings.ReplaceAll(input.CardNumber, " ", "")

	// Validate card details against database
	var card Card
	if err := db.Where("number = ?", cardNumber).First(&card).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid card number"})
		return
	}

	// Validate holder name (case-insensitive)
	if !strings.EqualFold(strings.TrimSpace(card.HolderName), strings.TrimSpace(input.HolderName)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Card holder name does not match"})
		return
	}

	// Validate expiry month
	if card.ExpMonth != input.ExpMonth {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid expiry month"})
		return
	}

	// Validate expiry year
	if card.ExpYear != input.ExpYear {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid expiry year"})
		return
	}

	// Validate CVV
	if card.CVV != input.CVV {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid CVV"})
		return
	}

	// Check if card is expired
	currentYear := time.Now().Year()
	currentMonth := int(time.Now().Month())
	if card.ExpYear < currentYear || (card.ExpYear == currentYear && card.ExpMonth < currentMonth) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Card has expired"})
		return
	}

	// Find active cart for user
	var cart Cart
	if err := db.Where("user_id = ? AND checked_out = ?", uint(userID), false).Preload("Items").First(&cart).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No active cart found"})
		return
	}

	if len(cart.Items) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cart is empty"})
		return
	}

	// Calculate total
	var total float64
	for _, item := range cart.Items {
		total += float64(item.Quantity) * item.UnitPrice
	}

	// Mark cart as checked out
	cart.CheckedOut = true
	if err := db.Save(&cart).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process payment"})
		return
	}

	// Create payment record
	payment := Payment{
		CartID:     cart.ID,
		Amount:     total,
		Provider:   "card",
		ProviderID: fmt.Sprintf("card_%d", card.ID),
		CreatedAt:  time.Now(),
	}
	if err := db.Create(&payment).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create payment record"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":        "Payment processed successfully",
		"payment_id":     payment.ID,
		"amount":         total,
		"transaction_id": payment.ProviderID,
	})
}

func SignInPage(c *gin.Context) {
	c.HTML(http.StatusOK, "signin.html", nil)
}

func SignIn(c *gin.Context) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var user User
	if err := db.Where("username = ?", input.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect username or password"})
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect username or password"})
		return
	}

	// Generate JWT token for successful login (same structure as SignUp)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"is_admin": user.IsAdmin,
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
	})

	tokenString, _ := token.SignedString(JwtSecretKey)

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"token":   tokenString,
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"is_admin": user.IsAdmin,
		},
	})
}

func connectDB() {
	dsn := "e_commerce:E-Commerce$1234@tcp(localhost:3306)/e_commerce?charset=utf8mb4&parseTime=True&loc=Local"
	dbConn, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("❌ Failed to connect to database:", err)
	}
	db = dbConn
	db.AutoMigrate(&User{}, &Product{}, &Cart{}, &CartItem{}, &Payment{}, &Card{})
	log.Println("✅ Database connected & migrated")

	// Seed a couple of demo cards if none exist
	var cardCount int64
	if err := db.Model(&Card{}).Count(&cardCount).Error; err == nil && cardCount == 0 {
		db.Create(&[]Card{
			{
				Number:     "4111111111111111",
				HolderName: "Test User",
				ExpMonth:   12,
				ExpYear:    time.Now().Year() + 1,
				CVV:        "123",
			},
			{
				Number:     "5555555555554444",
				HolderName: "Demo Card",
				ExpMonth:   6,
				ExpYear:    time.Now().Year() + 2,
				CVV:        "456",
			},
		})
		log.Println("✅ Seeded demo cards for payment testing")
	}
}

func main() {
	connectDB()

	r := gin.Default()
	r.LoadHTMLGlob("templates/*.html")
	r.Static("/static", "static")

	// Public shop & products
	r.GET("/shop", ShopPage)
	r.GET("/cart-page", CartPage)
	r.GET("/pay", PayPage)
	r.GET("/api/products", GetProducts)
	r.GET("/cart", GetCart)
	r.POST("/api/cart/add", AddToCart)
	r.DELETE("/api/cart/remove/:id", RemoveFromCart)
	r.POST("/pay", ProcessPayment)

	// Admin products page + API
	r.GET("/products", ProductsPage)
	r.GET("/admin/add-product", AddProductPage)
	r.GET("/admin/update-product", UpdateProductPage)
	r.POST("/api/admin/verify", VerifyAdminToken)
	r.GET("/api/admin/products", AdminGetProducts)
	r.GET("/api/admin/products/:id", AdminGetProduct)
	r.POST("/api/admin/products", AdminAddProduct)
	r.PUT("/api/admin/products/:id", AdminUpdateProduct)
	r.DELETE("/api/admin/products/:id", AdminDeleteProduct)

	r.GET("/sign-up", SignUpPage)
	r.POST("/sign-up", SignUp)

	r.GET("/sign-in", SignInPage)
	r.POST("/sign-in", SignIn)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}
