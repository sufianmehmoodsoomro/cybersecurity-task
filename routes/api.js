/**
 * Protected API Routes
 * All routes here require a valid API key
 */

const express = require('express');
const router = express.Router();
const { apiKeyAuth } = require('../middleware/apiKeyAuth');

// Apply API key authentication to ALL routes in this file
router.use(apiKeyAuth);

// GET /api/data/users  - Example protected endpoint
router.get('/users', (req, res) => {
  res.json({
    message: `Hello, ${req.apiClient}! Here is the protected data.`,
    users: [
      { id: 1, name: 'Alice', role: 'admin' },
      { id: 2, name: 'Bob', role: 'intern' },
    ],
  });
});

// GET /api/data/status - Another protected endpoint
router.get('/status', (req, res) => {
  res.json({
    status: 'All systems operational',
    client: req.apiClient,
    timestamp: new Date().toISOString(),
  });
});

// POST /api/data/submit - Protected POST endpoint
router.post('/submit', (req, res) => {
  const { data } = req.body;

  if (!data) {
    return res.status(400).json({ error: 'data field is required.' });
  }

  // Process the data...
  res.json({
    message: 'Data received successfully.',
    received: data,
    processedBy: req.apiClient,
  });
});

module.exports = router;
