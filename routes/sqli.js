/**
 * Week 5 - SQL Injection Routes
 * Shows vulnerable vs safe queries
 */

const express = require('express');
const router = express.Router();
const { getUserVulnerable, getUserSafe, insertUser } = require('../config/database');

// Insert test data
insertUser('admin', 'password123', 'admin@test.com');
insertUser('sufian', 'mypassword', 'sufian@test.com');

// ❌ VULNERABLE route - SQL Injection possible
// Test with: ' OR '1'='1
router.get('/vulnerable', (req, res) => {
  const username = req.query.username;
  
  if (!username) {
    return res.json({ error: 'username parameter required' });
  }

  getUserVulnerable(username, (err, rows) => {
    if (err) {
      return res.json({ error: err.message });
    }
    res.json({
      warning: '⚠️ This endpoint is VULNERABLE to SQL Injection!',
      query_used: `SELECT * FROM users WHERE username = '${username}'`,
      results: rows
    });
  });
});

// ✅ SAFE route - Protected with prepared statements
router.get('/safe', (req, res) => {
  const username = req.query.username;

  if (!username) {
    return res.json({ error: 'username parameter required' });
  }

  getUserSafe(username, (err, rows) => {
    if (err) {
      return res.json({ error: err.message });
    }
    res.json({
      message: '✅ This endpoint is SAFE - Using prepared statements!',
      results: rows
    });
  });
});

module.exports = router;