const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.json());
app.use(cookieParser());

const PORT = 3000;
const JWT_SECRET = 'your_jwt_secret_key'; // Replace with a strong secret in production

// Mock Database: In-memory user data storage
let users = [];

// Middleware for JWT Authentication
function authenticateJWT(req, res, next) {
    const token = req.cookies.token || req.headers['authorization'];
    if (!token) return res.status(401).json({ message: 'Unauthorized. Token required.' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ message: 'Invalid or expired token.' });
    }
}

// 1. User Registration API
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    // Check if the user already exists
    if (users.find((user) => user.email === email)) {
        return res.status(400).json({ message: 'User already exists.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { id: users.length + 1, username, email, password: hashedPassword };
    users.push(newUser);

    res.status(201).json({ message: 'User registered successfully.', user: { id: newUser.id, username, email } });
});

// 2. User Login API
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    const user = users.find((u) => u.email === email);
    if (!user) return res.status(401).json({ message: 'Invalid email or password.' });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ message: 'Invalid email or password.' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true });

    res.json({ message: 'Login successful.', token });
});

// 3. User Single Profile Read API
app.get('/profile', authenticateJWT, (req, res) => {
    const user = users.find((u) => u.id === req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found.' });

    res.json({ user: { id: user.id, username: user.username, email: user.email } });
});

// 4. All User Profiles Read API
app.get('/users', authenticateJWT, (req, res) => {
    const userProfiles = users.map((user) => ({ id: user.id, username: user.username, email: user.email }));
    res.json({ users: userProfiles });
});

// 5. Single User Profile Update API
app.put('/profile/update', authenticateJWT, (req, res) => {
    const { username, email } = req.body;
    const user = users.find((u) => u.id === req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found.' });

    user.username = username || user.username;
    user.email = email || user.email;

    res.json({ message: 'Profile updated successfully.', user: { id: user.id, username: user.username, email: user.email } });
});

// 6. Delete Single User API
app.delete('/profile/delete', authenticateJWT, (req, res) => {
    const userIndex = users.findIndex((u) => u.id === req.user.id);
    if (userIndex === -1) return res.status(404).json({ message: 'User not found.' });

    users.splice(userIndex, 1);
    res.clearCookie('token');
    res.json({ message: 'User deleted successfully.' });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
