/**
 * Bonus - Web Application Firewall (WAF)
 * Blocks malicious requests and attack patterns
 */

const fs = require('fs');
const path = require('path');

// Malicious patterns to block
const BLOCKED_PATTERNS = [
  // SQL Injection patterns
  /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
  /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i,
  /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i,
  
  // XSS patterns
  /((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)/i,
  /((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)/i,
  
  // Path traversal
  /\.\.\//,
  /\.\.\\/,
  
  // Command injection
  /;.*(ls|cat|rm|pwd|whoami|wget|curl)/i,
];

// Blocked IPs (can be updated dynamically)
const blockedIPs = new Set();

// Request counter per IP
const requestCounts = {};

function wafMiddleware(req, res, next) {
  const ip = req.ip;
  const url = req.originalUrl;
  const body = JSON.stringify(req.body || {});

  // Check 1: Blocked IP
  if (blockedIPs.has(ip)) {
    logWAF(ip, 'BLOCKED_IP', url);
    return res.status(403).json({
      error: '🛡️ WAF: Your IP has been blocked.'
    });
  }

  // Check 2: Malicious patterns in URL
  for (const pattern of BLOCKED_PATTERNS) {
    if (pattern.test(url) || pattern.test(body)) {
      blockedIPs.add(ip);
      logWAF(ip, 'MALICIOUS_PATTERN', url);
      return res.status(403).json({
        error: '🛡️ WAF: Malicious request detected and blocked!'
      });
    }
  }

  // Check 3: Too many requests (DDoS protection)
  requestCounts[ip] = (requestCounts[ip] || 0) + 1;
  if (requestCounts[ip] > 200) {
    blockedIPs.add(ip);
    logWAF(ip, 'DDOS_DETECTED', url);
    return res.status(429).json({
      error: '🛡️ WAF: Too many requests. IP blocked!'
    });
  }

  // Reset counts every 15 minutes
  setTimeout(() => {
    requestCounts[ip] = 0;
  }, 15 * 60 * 1000);

  console.log(`[WAF] ✅ Request allowed: ${req.method} ${url} from ${ip}`);
  next();
}

function logWAF(ip, type, url) {
  const entry = {
    timestamp: new Date().toISOString(),
    type,
    ip,
    url
  };
  console.warn(`[WAF] 🛡️ BLOCKED - ${type} from IP: ${ip}`);
  fs.appendFileSync(
    path.join(__dirname, '../logs/waf.log'),
    JSON.stringify(entry) + '\n'
  );
}

module.exports = { wafMiddleware };