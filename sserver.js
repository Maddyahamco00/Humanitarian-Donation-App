const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const port = 3307;

app.use(bodyParser.json());

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '1234567890#',
    database: 'newdonation_app'
});

db.connect((err) => {
    if (err) {
        throw err;
    }
    console.log('MySQL connected...');
});

// Middleware to authenticate using JWT
const authenticateToken = (req, res, next) => {
    const token = req.header('auth-token');
    if (!token) return res.status(401).send('Access Denied');

    try {
        const verified = jwt.verify(token, 'SECRET_KEY');
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send('Invalid Token');
    }
};

// User registration
app.post('/register', [
    body('email').isEmail().withMessage('Invalid email'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    // Check if user already exists
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            // Handle the error appropriately
            console.error('An error occurred while executing the query:', err);
            return res.status(500).send('An error occurred while checking the email');
        }
    
        // Check if results is defined and has a length property
        if (results && results.length > 0) {
            return res.status(400).send('Email already registered');
        }
    
   // });

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Save user to database
        const sql = 'INSERT INTO users (email, password) VALUES (?, ?)';
        db.query(sql, [email, hashedPassword], (err, result) => {
            if (err) throw err;
            res.send('User registered');
        });
    });
});

// User login
app.post('/login', [
    body('email').isEmail().withMessage('Invalid email'),
    body('password').exists().withMessage('Password is required')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (results.length === 0) {
            return res.status(400).send('Email or Password is incorrect');
        }

        const user = results[0];
        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) {
            return res.status(400).send('Invalid Password');
        }

        const token = jwt.sign({ id: user.id }, 'SECRET_KEY', { expiresIn: '1h' });
        res.header('auth-token', token).send('Logged in');
    });
});

// Create donor (authenticated)
app.post('/donors', authenticateToken, [
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Invalid email'),
    body('amount').isFloat({ gt: 0 }).withMessage('Amount must be greater than 0')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const donor = req.body;
    const sql = 'INSERT INTO donors SET ?';
    db.query(sql, donor, (err, result) => {
        if (err) throw err;
        res.send('Donor added...');
    });
});

// Create receiver (authenticated)
app.post('/receivers', authenticateToken, [
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Invalid email'),
    body('need').notEmpty().withMessage('Need is required')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const receiver = req.body;
    const sql = 'INSERT INTO receivers SET ?';
    db.query(sql, receiver, (err, result) => {
        if (err) throw err;
        res.send('Receiver added...');
    });
});

// Get all donors (authenticated)
app.get('/donors', authenticateToken, (req, res) => {
    const sql = 'SELECT * FROM donors';
    db.query(sql, (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

// Get all receivers (authenticated)
app.get('/receivers', authenticateToken, (req, res) => {
    const sql = 'SELECT * FROM receivers';
    db.query(sql, (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});