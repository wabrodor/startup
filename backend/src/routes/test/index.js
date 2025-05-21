// routes/testRoutes.js
const express = require('express');
const router = express.Router();

router.get('/error', (req, res) => {
  throw new Error('Test error triggered manually');
});

module.exports = router;
