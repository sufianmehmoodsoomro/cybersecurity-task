/**
 * Week 4 - Secured Express.js Server
 * Covers: Rate Limiting, CORS, Security Headers, CSP, HSTS, API Key Auth
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');

const app = express();

// ─────────────────────────────────────────────
// 1. LOGGING (for intrusion detection)
// ─────────────────────────────────────────────
const accessLogStream = fs.createWriteStream(
  path.join(__dirname, 'logs', 'access.log'),
  { flags: 'a' }
);
app.use(morgan('combined', { stream: accessLogStream }));
app.use(morgan('dev')); // also log to console

// ─────────────────────────────────────────────
// 2. BODY PARSER
// ─────────────────────────────────────────────
app.use(express.json({ limit: '10kb' })); // prevent large payload attacks
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ─────────────────────────────────────────────
// 3. SECURITY HEADERS via Helmet (CSP + HSTS)
// ─────────────────────────────────────────────
app.use(
  helmet({
    // Content Security Policy - prevents XSS / script injection
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],          // no inline scripts
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'none'"],
        frameSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },

    // HTTP Strict Transport Security - forces HTTPS
    hsts: {
      maxAge: 31536000,        // 1 year in seconds
      includeSubDomains: true,
      preload: true,
    },

    // Prevent clickjacking
    frameguard: { action: 'deny' },

    // Hide Express fingerprint
    hidePoweredBy: true,

    // Prevent MIME-type sniffing
    noSniff: true,

    // Block cross-site scripting (legacy browsers)
    xssFilter: true,
  })
);

// ─────────────────────────────────────────────
// 4. CORS CONFIGURATION
// ─────────────────────────────────────────────
const allowedOrigins = [
  'http://localhost:3000',
  'https://yourdomain.com', // replace with your frontend domain
];

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (e.g., mobile apps, Postman in dev)
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error(`CORS blocked: origin ${origin} not allowed`));
      }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key'],
    credentials: true,
    optionsSuccessStatus: 200,
  })
);

// ─────────────────────────────────────────────
// 5. RATE LIMITING
// ─────────────────────────────────────────────

// General API limiter - 100 requests per 15 minutes
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 429,
    error: 'Too many requests. Please try again after 15 minutes.',
  },
  handler: (req, res, next, options) => {
    console.warn(`[RATE LIMIT] IP ${req.ip} exceeded general limit`);
    logSuspiciousActivity(req, 'RATE_LIMIT_EXCEEDED');
    res.status(options.statusCode).json(options.message);
  },
});

// Strict login limiter - 5 attempts per 15 minutes
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 429,
    error: 'Too many login attempts. Account temporarily locked. Try again in 15 minutes.',
  },
  handler: (req, res, next, options) => {
    console.warn(`[SECURITY ALERT] Multiple failed login attempts from IP: ${req.ip}`);
    logSuspiciousActivity(req, 'BRUTE_FORCE_ATTEMPT');
    res.status(options.statusCode).json(options.message);
  },
});

app.use('/api/', generalLimiter);

// ─────────────────────────────────────────────
// 6. ROUTES
// ─────────────────────────────────────────────
const authRoutes = require('./routes/auth');
const apiRoutes = require('./routes/api');

app.use('/api/auth', loginLimiter, authRoutes);
app.use('/api/data', apiRoutes);
const sqliRoutes = require('./routes/sqli');
app.use('/api/sqli', sqliRoutes);
const csrfRoutes = require('./routes/csrf');
app.use('/api/csrf', csrfRoutes);

// Health check (no auth needed)
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ─────────────────────────────────────────────
// 7. ERROR HANDLER
// ─────────────────────────────────────────────
app.use((err, req, res, next) => {
  // CORS errors
  if (err.message && err.message.startsWith('CORS blocked')) {
    return res.status(403).json({ error: err.message });
  }
  console.error('[ERROR]', err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// ─────────────────────────────────────────────
// HELPER: Log suspicious activity to file
// ─────────────────────────────────────────────
function logSuspiciousActivity(req, type) {
  const entry = {
    timestamp: new Date().toISOString(),
    type,
    ip: req.ip,
    method: req.method,
    path: req.path,
    userAgent: req.get('User-Agent'),
  };
  fs.appendFileSync(
    path.join(__dirname, 'logs', 'suspicious.log'),
    JSON.stringify(entry) + '\n'
  );
}

// ─────────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ Secure server running on port ${PORT}`);
  console.log(`🔒 Security headers: ENABLED`);
  console.log(`🚦 Rate limiting: ENABLED`);
  console.log(`🌐 CORS: ENABLED (whitelist mode)`);
});

module.exports = app;
