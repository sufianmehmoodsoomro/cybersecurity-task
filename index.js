const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const validator = require('validator');

const winston = require('winston');

const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});

logger.info('Application started');
const app = express();

// SECURITY FIX 1: Helmet - Secure Headers
app.use(helmet());

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ 
  secret: 'supersecretkey123', 
  resave: false, 
  saveUninitialized: false,
  cookie: { secure: false }
}));

// SECURITY FIX 2: Hashed Passwords with bcrypt
const users = [
  { id: 1, username: 'admin', password: bcrypt.hashSync('admin123', 10) },
  { id: 2, username: 'user', password: bcrypt.hashSync('password', 10) }
];

const JWT_SECRET = 'jwt_secret_key_123';

// Home page
app.get('/', (req, res) => {
  if (req.session.user) {
    res.send(`
      <h1>Welcome ${validator.escape(req.session.user)}!</h1>
      <a href="/logout">Logout</a><br><br>
      <h2>Search Users</h2>
      <form method="GET" action="/search">
        <input name="q" placeholder="Search...">
        <button>Search</button>
      </form>
    `);
  } else {
    res.redirect('/login');
  }
});

// Login page
app.get('/login', (req, res) => {
  res.send(`
    <h1>Login</h1>
    <form method="POST" action="/login">
      <input name="username" placeholder="Username"><br><br>
      <input name="password" type="password" placeholder="Password"><br><br>
      <button>Login</button>
    </form>
  `);
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // SECURITY FIX 3: Input Validation
  if (!username || !password) {
    return res.send('<h1>Error: Fields cannot be empty!</h1><a href="/login">Back</a>');
  }

  if (!validator.isAlphanumeric(username)) {
    return res.send('<h1>Error: Invalid username!</h1><a href="/login">Back</a>');
  }

  // SECURITY FIX 4: bcrypt password check
  const user = users.find(u => u.username === username);
  if (user && await bcrypt.compare(password, user.password)) {
    req.session.user = username;

    // SECURITY FIX 5: JWT Token
    const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '1h' });
    req.session.token = token;

    res.redirect('/');
  } else {
    res.send('<h1>Login Failed!</h1><a href="/login">Try Again</a>');
  }
});

// Search - XSS FIXED
app.get('/search', (req, res) => {
  const query = req.query.q || '';

  // SECURITY FIX 6: Input Sanitization - XSS Fixed
  const safeQuery = validator.escape(query);
  res.send(`
    <h1>Search Results for: ${safeQuery}</h1>
    <a href="/">Back</a>
  `);
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

app.listen(3000, () => {
  console.log('Secure Server running on http://localhost:3000');
});