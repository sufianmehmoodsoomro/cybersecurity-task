/**
 * Auth Routes - Login with brute-force monitoring
 * Week 4: Intrusion Detection & Monitoring
 */

const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

// Track failed login attempts per IP in memory
// In production, use Redis for this
const failedAttempts = {};
const LOCKOUT_THRESHOLD = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

// ─────────────────────────────────────────────
// POST /api/auth/login
// ─────────────────────────────────────────────
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;

  // Validate input
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  // Check if IP is currently locked out
  if (isLockedOut(ip)) {
    logAuthEvent(ip, username, 'LOCKOUT_BLOCKED');
    return res.status(429).json({
      error: 'Account temporarily locked due to multiple failed attempts. Try again in 15 minutes.',
    });
  }

  // ⚠️ DEMO: Replace this block with your real user lookup + bcrypt.compare()
  const DEMO_USERS = {
    admin: 'SecurePass123!',
    intern: 'Intern@2026',
  };

  const isValid = DEMO_USERS[username] === password;

  if (!isValid) {
    // Record failed attempt
    recordFailedAttempt(ip, username);
    const remaining = LOCKOUT_THRESHOLD - (failedAttempts[ip]?.count || 0);
    logAuthEvent(ip, username, 'FAILED_LOGIN');

    return res.status(401).json({
      error: `Invalid credentials. ${remaining} attempt(s) remaining before lockout.`,
    });
  }

  // Success - clear failed attempts for this IP
  clearFailedAttempts(ip);
  logAuthEvent(ip, username, 'LOGIN_SUCCESS');

  // In production: generate a proper JWT here
  res.json({
    message: 'Login successful.',
    user: username,
    token: 'demo-token-replace-with-jwt', // placeholder
  });
});

// ─────────────────────────────────────────────
// POST /api/auth/logout
// ─────────────────────────────────────────────
router.post('/logout', (req, res) => {
  // In production: blacklist the JWT / clear session
  res.json({ message: 'Logged out successfully.' });
});

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────
function isLockedOut(ip) {
  const record = failedAttempts[ip];
  if (!record) return false;
  if (record.count >= LOCKOUT_THRESHOLD) {
    const elapsed = Date.now() - record.firstAttempt;
    if (elapsed < LOCKOUT_DURATION_MS) return true;
    // Lockout expired - clear record
    delete failedAttempts[ip];
  }
  return false;
}

function recordFailedAttempt(ip, username) {
  if (!failedAttempts[ip]) {
    failedAttempts[ip] = { count: 0, firstAttempt: Date.now(), usernames: [] };
  }
  failedAttempts[ip].count++;
  failedAttempts[ip].usernames.push(username);

  // Alert if threshold reached
  if (failedAttempts[ip].count >= LOCKOUT_THRESHOLD) {
    console.error(`🚨 [SECURITY ALERT] Brute-force detected from IP: ${ip}`);
    console.error(`   Tried usernames: ${[...new Set(failedAttempts[ip].usernames)].join(', ')}`);
  }
}

function clearFailedAttempts(ip) {
  delete failedAttempts[ip];
}

function logAuthEvent(ip, username, event) {
  const entry = {
    timestamp: new Date().toISOString(),
    event,
    ip,
    username,
  };
  fs.appendFileSync(
    path.join(__dirname, '../logs/auth-events.log'),
    JSON.stringify(entry) + '\n'
  );
}

module.exports = router;
