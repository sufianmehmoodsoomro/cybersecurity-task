const express = require('express');
const router = express.Router();
const csrf = require('csurf');
const cookieParser = require('cookie-parser');

router.use(cookieParser());

const csrfProtection = csrf({ cookie: true });

router.get('/token', csrfProtection, (req, res) => {
  res.json({
    message: '✅ CSRF Token generated!',
    csrfToken: req.csrfToken()
  });
});

router.post('/submit', csrfProtection, (req, res) => {
  res.json({
    message: '✅ CSRF check passed! Form submitted.',
    data: req.body
  });
});

router.post('/submit-no-csrf', (req, res) => {
  res.json({
    warning: '⚠️ No CSRF protection here!',
    data: req.body
  });
});

module.exports = router;