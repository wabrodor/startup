const rateLimit = require('express-rate-limit');

// Limit OTP requests: max 5 per 15 minutes per IP
const otpRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
   message: {
    error: 'You’ve exceeded the OTP limit. Try again in 15 minutes.',
  },
  statusCode: 429,
  standardHeaders: true,
  legacyHeaders: false
});

module.exports = otpRateLimiter

