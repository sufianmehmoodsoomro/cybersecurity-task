/**
 * API Key Authentication Middleware
 * Validates x-api-key header against a stored list of valid keys
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// In production, store these in a database (hashed)
// For this task, we use a config file
const API_KEYS_FILE = path.join(__dirname, '../config/apiKeys.json');

function loadApiKeys() {
  try {
    const data = fs.readFileSync(API_KEYS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error('[AUTH] Could not load API keys file:', err.message);
    return {};
  }
}

/**
 * Middleware: Verify API Key from request header
 * Usage: add to any route → router.get('/secure', apiKeyAuth, handler)
 */
function apiKeyAuth(req, res, next) {
  const apiKey = req.headers['x-api-key'];

  if (!apiKey) {
    logFailedAuth(req, 'MISSING_API_KEY');
    return res.status(401).json({
      error: 'Unauthorized: API key is required. Include x-api-key header.',
    });
  }

  const keys = loadApiKeys();

  // Hash the incoming key for comparison (timing-safe)
  const hashedInput = hashKey(apiKey);
  const matchedClient = Object.entries(keys).find(
    ([client, storedHash]) => timingSafeCompare(hashedInput, storedHash)
  );

  if (!matchedClient) {
    logFailedAuth(req, 'INVALID_API_KEY');
    return res.status(403).json({
      error: 'Forbidden: Invalid API key.',
    });
  }

  // Attach client info to request
  req.apiClient = matchedClient[0];
  console.log(`[AUTH] ✅ Authenticated client: ${req.apiClient} from IP: ${req.ip}`);
  next();
}

/**
 * Hash a key using SHA-256
 */
function hashKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

/**
 * Timing-safe string comparison to prevent timing attacks
 */
function timingSafeCompare(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/**
 * Log failed auth attempts
 */
function logFailedAuth(req, reason) {
  const log = {
    timestamp: new Date().toISOString(),
    reason,
    ip: req.ip,
    path: req.originalUrl,
    userAgent: req.get('User-Agent'),
  };
  console.warn(`[AUTH FAILURE] ${reason} from IP: ${req.ip}`);
  fs.appendFileSync(
    path.join(__dirname, '../logs/auth-failures.log'),
    JSON.stringify(log) + '\n'
  );
}

/**
 * Utility: Generate a new secure API key (run once to create keys)
 * Usage in terminal: node -e "require('./middleware/apiKeyAuth').generateKey('myApp')"
 */
function generateKey(clientName) {
  const rawKey = crypto.randomBytes(32).toString('hex'); // 64-char hex key
  const hashed = hashKey(rawKey);

  let keys = {};
  try {
    keys = JSON.parse(fs.readFileSync(API_KEYS_FILE, 'utf8'));
  } catch (_) {}

  keys[clientName] = hashed;
  fs.writeFileSync(API_KEYS_FILE, JSON.stringify(keys, null, 2));

  console.log(`\n✅ API Key generated for "${clientName}":`);
  console.log(`   Raw Key (share with client): ${rawKey}`);
  console.log(`   Hashed (stored in config):   ${hashed}`);
  console.log(`\n⚠️  Store the raw key safely - it won't be shown again!\n`);
  return rawKey;
}

module.exports = { apiKeyAuth, generateKey };
