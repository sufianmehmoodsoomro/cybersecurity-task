# Security Audit Report
**Intern:** Sufian Mehmood Soomro
**Company:** Developers Hub
**Date:** 20 June 2026

---

## Week 4: API Security & Threat Detection

### 1. Rate Limiting
- **Tool:** express-rate-limit
- **Result:** Login blocked after 5 failed attempts
- **Status:** ✅ PASS

### 2. API Key Authentication
- **Tool:** Custom middleware
- **Result:** Unauthorized access blocked (401)
- **Status:** ✅ PASS

### 3. Security Headers
- **Tool:** Helmet.js
- **Result:** CSP, HSTS, X-Frame-Options all enabled
- **Status:** ✅ PASS

### 4. CORS Protection
- **Tool:** cors middleware
- **Result:** Only whitelisted origins allowed
- **Status:** ✅ PASS

### 5. Intrusion Detection
- **Tool:** Custom monitor.js
- **Result:** Brute force detected and alerted
- **Status:** ✅ PASS

---

## Week 5: Ethical Hacking & Vulnerabilities

### 1. SQL Injection Test
- **Tool:** Manual testing
- **Vulnerable Query:** SELECT * FROM users WHERE username = '' OR '1'='1'
- **Result:** All user data exposed on vulnerable endpoint
- **Fix:** Prepared statements applied on safe endpoint
- **Status:** ✅ FIXED

### 2. CSRF Protection
- **Tool:** csurf middleware
- **Result:** CSRF token generated and validated
- **Status:** ✅ PASS

---

## Week 6: Security Audit

### OWASP ZAP Scan Results
- **Target:** http://localhost:5000
- **Alerts Found:** 2

| Alert | Risk | Status |
|-------|------|--------|
| CSP: No Fallback Directive | Medium | Noted |
| User Agent Fuzzer | Informational | Noted |

---

## Summary

| Week | Task | Status |
|------|------|--------|
| Week 4 | Rate Limiting | ✅ Done |
| Week 4 | API Key Auth | ✅ Done |
| Week 4 | Security Headers | ✅ Done |
| Week 4 | CORS | ✅ Done |
| Week 4 | Monitoring | ✅ Done |
| Week 5 | SQL Injection Fix | ✅ Done |
| Week 5 | CSRF Protection | ✅ Done |
| Week 6 | OWASP ZAP Audit | ✅ Done |