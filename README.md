# E-Commerce API

A full-featured e-commerce platform built with Go, featuring user authentication, product management, shopping cart, and payment processing.

**Project Page:** [https://roadmap.sh/projects/ecommerce-api](https://roadmap.sh/projects/ecommerce-api)

## Features

- **User Authentication**: JWT-based sign up and sign in
- **Product Management**: Admin panel for CRUD operations on products
- **Shopping Cart**: Add, remove, and manage cart items
- **Payment Processing**: Card validation and payment gateway integration
- **Inventory Management**: Stock tracking and validation
- **RESTful API**: Clean API endpoints for all operations

## Tech Stack

- **Backend**: Go (Golang)
- **Framework**: Gin
- **Database**: MySQL
- **ORM**: GORM
- **Authentication**: JWT (JSON Web Tokens)
- **Frontend**: HTML templates with CSS

## Getting Started

### Prerequisites

- Go 1.25.0 or higher
- MySQL database
- Git

### Installation

1. Clone the repository:
```bash
git clone https://github.com/ParsaSoroush/E-Commerce-API.git
cd E-Commerce-API
```

2. Install dependencies:
```bash
go mod download
```

3. Configure database connection in `main.go` (update DSN string)

4. Run the application:
```bash
go run main.go
```

The server will start on `http://localhost:8080` (or the port specified in the `PORT` environment variable).

## API Endpoints

### Public Endpoints
- `GET /shop` - Shop page
- `GET /api/products` - Get all products
- `GET /sign-up` - Sign up page
- `POST /sign-up` - Register new user
- `GET /sign-in` - Sign in page
- `POST /sign-in` - User login

### Authenticated Endpoints
- `GET /cart-page` - Cart page
- `GET /cart` - Get user's cart
- `POST /api/cart/add` - Add product to cart
- `DELETE /api/cart/remove/:id` - Remove item from cart
- `GET /pay` - Payment page
- `POST /pay` - Process payment

### Admin Endpoints
- `GET /products` - Admin products page
- `GET /api/admin/products` - Get all products (admin)
- `POST /api/admin/products` - Create product
- `PUT /api/admin/products/:id` - Update product
- `DELETE /api/admin/products/:id` - Delete product

## Project Structure

```
E-Commerce-API/
├── main.go              # Main application file
├── go.mod               # Go module dependencies
├── templates/           # HTML templates
├── static/             # CSS and static assets
└── README.md           # This file
```