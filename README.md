# Week 4 — Advanced Threat Detection & Web Security

**Internship:** Developers Hub | Cybersecurity Track  
**Intern:** [Your Name]  
**Deadline:** 30th June, 2026

---

## What Was Implemented

This project secures a Node.js/Express API with three layers of defence:

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Intrusion Detection | Custom log monitor (`monitor.js`) | Detects brute-force, rate-limit abuse |
| API Security | `express-rate-limit`, API Key auth | Blocks brute-force, authenticates callers |
| Security Headers | `helmet` (CSP + HSTS) | Prevents XSS, forces HTTPS, stops clickjacking |
| CORS | `cors` middleware | Restricts cross-origin requests |

---

## Project Structure

```
week4-security/
├── server.js              ← Main Express app (all security middleware wired here)
├── monitor.js             ← Real-time log watcher (Fail2Ban equivalent for Windows)
├── package.json
├── middleware/
│   └── apiKeyAuth.js      ← API key validation middleware
├── routes/
│   ├── auth.js            ← Login endpoint with brute-force tracking
│   └── api.js             ← Protected routes (require API key)
├── config/
│   └── apiKeys.json       ← Hashed API keys storage
└── logs/                  ← Auto-created at runtime
    ├── access.log         ← All HTTP requests
    ├── auth-events.log    ← Login successes/failures
    ├── suspicious.log     ← Rate-limit violations
    └── alerts.log         ← High-severity security alerts
```

---

## Setup Instructions

### Step 1 — Install dependencies

```bash
cd week4-security
npm install
```

### Step 2 — Generate your first API key

```bash
npm run generate-key myApp
```

Copy the **Raw Key** shown in the terminal. That is what clients send in the `x-api-key` header.

### Step 3 — Start the server

```bash
npm start
```

### Step 4 — Start the security monitor (in a second terminal)

```bash
npm run monitor
```

---

## Testing the Security Features

### Test 1: Rate Limiting (Brute Force Protection)

Send 6 rapid login requests — the 6th should be blocked:

```bash
# Using curl (run 6 times quickly)
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"wrong\"}"
```

Expected: After 5 attempts, you receive:
```json
{ "error": "Too many login attempts. Account temporarily locked. Try again in 15 minutes." }
```

---

### Test 2: API Key Authentication

**Without a key (should fail):**
```bash
curl http://localhost:5000/api/data/users
```
Response: `401 Unauthorized`

**With a valid key (should succeed):**
```bash
curl http://localhost:5000/api/data/users \
  -H "x-api-key: YOUR_RAW_KEY_HERE"
```
Response: `200 OK` with user data

---

### Test 3: CORS Blocking

Open browser DevTools console on any non-whitelisted site and run:
```javascript
fetch('http://localhost:5000/api/data/status', {
  headers: { 'x-api-key': 'your-key' }
}).then(r => r.json()).then(console.log).catch(console.error)
```
Expected: CORS error — request blocked.

---

### Test 4: Security Headers

```bash
curl -I http://localhost:5000/health
```

You should see these headers in the response:
```
Content-Security-Policy: default-src 'self'; ...
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
```

---

## Security Features Explained

### 1. Intrusion Detection & Monitoring

**File:** `monitor.js`

Since Fail2Ban is Linux-only, this custom script provides equivalent protection on Windows:

- Watches log files in real time using `fs.watch()`
- Counts failed login attempts per IP address
- Triggers alerts when an IP exceeds the threshold (default: 3 events)
- Prints the exact Windows Firewall command to block the offending IP

**To block an IP on Windows (run as Administrator):**
```cmd
netsh advfirewall firewall add rule name="Block <IP>" dir=in action=block remoteip=<IP>
```

---

### 2. Rate Limiting

**File:** `server.js` (lines ~70–110)  
**Package:** `express-rate-limit`

Two separate limiters are configured:

| Limiter | Route | Limit | Window |
|---------|-------|-------|--------|
| General | `/api/*` | 100 requests | 15 min |
| Login | `/api/auth/login` | 5 requests | 15 min |

---

### 3. CORS (Cross-Origin Resource Sharing)

**File:** `server.js` (lines ~115–140)

- Only origins in the `allowedOrigins` array can make requests
- Other origins receive a `403 Forbidden` response
- Allowed HTTP methods: GET, POST, PUT, DELETE

**To add your frontend domain:**
```javascript
const allowedOrigins = [
  'http://localhost:3000',
  'https://YOUR-DOMAIN.com',  // ← add here
];
```

---

### 4. API Key Authentication

**File:** `middleware/apiKeyAuth.js`

- Clients must send their key in the `x-api-key` header
- Keys are stored as **SHA-256 hashes** (raw key is never stored)
- Uses `crypto.timingSafeEqual()` to prevent timing attacks
- Failed auth attempts are logged to `logs/auth-failures.log`

---

### 5. Security Headers (Helmet)

**File:** `server.js` (lines ~50–70)  
**Package:** `helmet`

| Header | Value | Protects Against |
|--------|-------|-----------------|
| `Content-Security-Policy` | `default-src 'self'` | XSS / script injection |
| `Strict-Transport-Security` | `max-age=31536000` | Forces HTTPS for 1 year |
| `X-Frame-Options` | `DENY` | Clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing attacks |
| `X-XSS-Protection` | `1; mode=block` | Legacy XSS filter |

---

## Deliverables Checklist

- [x] Real-time intrusion detection (log monitoring + alert system)
- [x] Alert system for multiple failed login attempts
- [x] Rate limiting on all API endpoints (`express-rate-limit`)
- [x] Rate limiting on login with lockout
- [x] CORS properly configured with whitelist
- [x] API key authentication middleware
- [x] Content Security Policy (CSP) header
- [x] HSTS header enforcing HTTPS
- [x] All other Helmet security headers
- [x] Detailed README documentation

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `express` | ^4.18.2 | Web framework |
| `helmet` | ^7.1.0 | Security headers (CSP, HSTS, etc.) |
| `cors` | ^2.8.5 | Cross-origin policy |
| `express-rate-limit` | ^7.1.5 | Rate limiting |
| `morgan` | ^1.10.0 | HTTP request logging |

---

*Week 4 of Cybersecurity Internship — Developers Hub*
