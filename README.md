# User Login System with Express.js

This is a simple user authentication system built using **Express.js**, **bcrypt**, and **jsonwebtoken (JWT)**. The system supports **user registration**, **login**, **profile viewing**, and **admin-only access**. The project demonstrates how to implement user authentication, securely store passwords, and manage user roles.

## Features

- **User Registration**: Allows new users to register with email, password, and optional role.
- **User Login**: Validates user credentials and generates a JSON Web Token (JWT) for authentication.
- **Profile Route**: A protected route to retrieve the user's profile information.
- **Admin Route**: A protected route that only allows users with the **admin** role to access it.
- **JWT Authentication**: The system uses JSON Web Tokens (JWT) for session management, providing a secure way to handle authentication.
- **Password Hashing**: Passwords are hashed using **bcrypt** to ensure they are stored securely.

## Technologies Used

- **Node.js**: JavaScript runtime for building the server.
- **Express.js**: Web framework for Node.js to handle routing and middleware.
- **bcrypt**: A library for securely hashing passwords.
- **jsonwebtoken (JWT)**: A library for generating and verifying JWTs used for user authentication.

## Installation

### Prerequisites

- **Node.js**: Make sure you have [Node.js](https://nodejs.org/) installed on your machine.

### Steps

1. **Clone the repository**:

    ```bash
    git clone https://github.com/your-username/user-login.git
    cd user-login
    ```

2. **Install dependencies**:

    ```bash
    npm install
    ```

3. **Create a `.env` file**:
   
    Add your secret key in a `.env` file for JWT signing:
    ```
    SECRET_KEY=your-secret-key
    ```

4. **Start the server**:

    ```bash
    node app.js
    ```

    The server will start and listen on port `5000`. Open your browser and navigate to `http://localhost:5000` to test the endpoints.

## API Endpoints

### **POST /api/register**
- **Description**: Register a new user.
- **Request body**:
    ```json
    {
        "email": "user@example.com",
        "password": "password123",
        "role": "user"  // Optional, default is "user"
    }
    ```
- **Response**:
    - **Success**: `{"message": "User registered successfully."}`
    - **Error**: `{"message": "Email and password are required."}` or `{"message": "User already registered."}`

### **POST /api/login**
- **Description**: Login and receive a JWT token.
- **Request body**:
    ```json
    {
        "email": "user@example.com",
        "password": "password123"
    }
    ```
- **Response**:
    - **Success**: `{"message": "Login successful.", "token": "your-jwt-token"}`
    - **Error**: `{"message": "Invalid email or password."}`

### **GET /api/profile**
- **Description**: Retrieve the logged-in user's profile. Requires a valid JWT token in the `Authorization` header.
- **Request headers**:
    ```
    Authorization: Bearer <your-jwt-token>
    ```
- **Response**:
    - **Success**: `{"message": "Profile fetched successfully.", "user": {"email": "user@example.com", "role": "user"}}`
    - **Error**: `{"message": "Access denied. No token provided."}` or `{"message": "Invalid token."}`

### **GET /api/admin**
- **Description**: Admin-only route. Only users with the **admin** role can access it. Requires a valid JWT token in the `Authorization` header.
- **Request headers**:
    ```
    Authorization: Bearer <your-jwt-token>
    ```
- **Response**:
    - **Success**: `{"message": "Welcome, Admin!", "user": {"email": "admin@example.com", "role": "admin"}}`
    - **Error**: `{"message": "Access denied. Admins only."}`

## Testing the API

You can use **Postman** or any other API testing tool to test the API routes.

1. **Register a user** by sending a POST request to `/api/register`.
2. **Login** to obtain a JWT token by sending a POST request to `/api/login`.
3. **Access the profile** by sending a GET request to `/api/profile` with the JWT token in the Authorization header.
4. **Access the admin route** by sending a GET request to `/api/admin` with the JWT token in the Authorization header (only if the user is an admin).

## Security Considerations

- **JWT Expiry**: The JWT token expires in **1 hour** to improve security.
- **Password Hashing**: Passwords are hashed using bcrypt before being stored, ensuring that passwords are not saved in plaintext.
- **Role-Based Access Control**: The app includes role-based access control for the admin route, restricting access to only users with the "admin" role.

## Future Improvements

- Add database integration (e.g., MongoDB, PostgreSQL) to persist user data.
- Implement password reset functionality.
- Add account lockout after multiple failed login attempts for additional security.
- Implement password complexity rules to ensure strong passwords.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
