/**
 * Bonus - Zero Trust Security Middleware
 * Every request must be verified - trust nobody!
 */

const jwt = require('jsonwebtoken');

const JWT_SECRET = 'your-super-secret-key-2026';

// Zero Trust - verify every single request
function zeroTrustMiddleware(req, res, next) {
  console.log(`[ZERO TRUST] Verifying request: ${req.method} ${req.path}`);

  // Check 1: API Key must be present
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) {
    console.warn(`[ZERO TRUST] BLOCKED - No API key from IP: ${req.ip}`);
    return res.status(401).json({
      error: 'Zero Trust: API key required for every request.'
    });
  }

  // Check 2: Request must not be too large
  const contentLength = req.headers['content-length'];
  if (contentLength && parseInt(contentLength) > 10240) {
    console.warn(`[ZERO TRUST] BLOCKED - Request too large from IP: ${req.ip}`);
    return res.status(413).json({
      error: 'Zero Trust: Request size exceeded limit.'
    });
  }

  // Check 3: User Agent must be present
  const userAgent = req.headers['user-agent'];
  if (!userAgent) {
    console.warn(`[ZERO TRUST] BLOCKED - No user agent from IP: ${req.ip}`);
    return res.status(400).json({
      error: 'Zero Trust: User agent required.'
    });
  }

  console.log(`[ZERO TRUST] ✅ Request verified from IP: ${req.ip}`);
  next();
}

// Generate JWT token
function generateToken(username) {
  return jwt.sign(
    { username, timestamp: Date.now() },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
}

// Verify JWT token
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json({
      error: 'Zero Trust: JWT token required.'
    });
  }

  try {
    const decoded = jwt.verify(token.replace('Bearer ', ''), JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({
      error: 'Zero Trust: Invalid or expired token.'
    });
  }
}

module.exports = { zeroTrustMiddleware, generateToken, verifyToken };