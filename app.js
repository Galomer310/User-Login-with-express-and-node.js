const express = require("express"); // The Express.js framework used to handle routing and creating the server.
const bcrypt = require("bcrypt"); // A library used to hash passwords securely.
const jwt = require("jsonwebtoken"); // A library to generate and verify JSON Web Tokens (JWTs) for authentication.

const app = express(); // The Express application instance that will handle all routes and middleware.
const PORT = 5000;

// Secret key for JWT
const SECRET_KEY = "your-secret-key";

// In-memory database for simplicity
const users = [];

// Middleware to parse JSON
app.use(express.json()); // This line of code tells Express to automatically parse incoming request bodies with JSON format. This will allow us to easily handle req.body in our routes.

// Middleware to verify the JWT token
const authenticateToken = (req, res, next) => {
  // This is a middleware function that checks if the incoming request contains a valid JWT token in the Authorization header.
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res
      .status(401)
      .json({ message: "Access denied. No token provided." });

  const token = authHeader.split(" ")[1]; // Extract the token  //  It splits the header to extract the token and then verifies it
  try {
    const decoded = jwt.verify(token, SECRET_KEY); // If the token is valid, the decoded user data is attached to req.user and the request moves on to the next middleware or route handler.
    req.user = decoded; // Attach user data to the request
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token." }); // If the token is invalid or missing, it responds with a 401 status (unauthorized).
  }
};

// Middleware to verify admin role
const verifyAdmin = (req, res, next) => {
  // This middleware checks if the user making the request is an admin.
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Access denied. Admins only." }); // It reads the role from req.user (which was set during token verification) and compares it to "admin". If the user is not an admin, it responds with a 403 status (forbidden).
  }
  next(); // If the user is an admin, it calls next() to continue processing the request.
};

// Route: User Registration
app.post("/api/register", async (req, res) => {
  // This route handles user registration.
  const { email, password, role } = req.body;

  // Validate input
  if (!email || !password)
    // It first validates the input by checking that both email and password are provided.
    return res
      .status(400) // If the user already exists (by checking the email), it responds with a 400 error.
      .json({ message: "Email and password are required." });

  // Check if user already exists
  const existingUser = users.find((user) => user.email === email);
  if (existingUser)
    return res.status(400).json({ message: "User already registered." });

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10); // The password is hashed using bcrypt.hash() before storing it. This ensures that even if someone accesses the "users" array, they can't see the raw password.

  // Create new user
  const newUser = { email, password: hashedPassword, role: role || "user" }; // Default role is 'user'
  users.push(newUser); // A new user is added to the users array

  res.status(201).json({ message: "User registered successfully." });
});

// Route: User Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  // Validate input
  if (!email || !password)
    // It checks if both the email and password are provided.
    return res
      .status(400) //  If missing, it responds with a 400 error.
      .json({ message: "Email and password are required." });

  // Find the user
  const user = users.find((user) => user.email === email);
  if (!user)
    // The user is looked up in the users array, and if the user is not found, it responds with a 400 error.
    return res.status(400).json({ message: "Invalid email or password." });

  // Verify the password
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid)
    // The password is compared using bcrypt.compare(). If the password is incorrect, it returns an error.
    return res.status(400).json({ message: "Invalid email or password." });

  // Generate JWT
  const token = jwt.sign({ email: user.email, role: user.role }, SECRET_KEY, {
    expiresIn: "1h",
  }); // If the credentials are correct, a JWT token is generated using jwt.sign(). The token includes the user's email and role and expires in 1 hour.

  res.json({ message: "Login successful.", token });
}); // The token is returned to the user so they can use it for subsequent requests.

// Route: User Profile (protected)
app.get("/api/profile", authenticateToken, (req, res) => {
  // The authenticateToken middleware is used to verify that the request contains a valid JWT token.
  res.json({ message: "Profile fetched successfully.", user: req.user }); // If the token is valid, the user's information (from req.user) is returned in the response.
});

// Route: Admin-only Access (protected, admin-only)
app.get("/api/admin", authenticateToken, verifyAdmin, (req, res) => {
  // The authenticateToken middleware is used to verify the JWT token.
  res.json({ message: "Welcome, Admin!", user: req.user }); // The verifyAdmin middleware checks if the user has the admin role.
}); // If both checks pass, the admin user gets a welcome message along with their user data.

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
