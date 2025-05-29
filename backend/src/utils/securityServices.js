const SecurityLog = require('../models/Security');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');

class SecurityService {
  static async logSecurityEvent(userId, action, details, req, riskLevel = 'LOW') {
    try {
      await SecurityLog.create({
        userId,
        action,
        details,
        ipAddress: this.getClientIP(req),
        userAgent: req.get('User-Agent'),
        riskLevel
      });
    } catch (error) {
      console.error('Security logging error:', error);
    }
  }

  static getClientIP(req) {
    return req.ip || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress ||
           (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
           req.headers['x-forwarded-for']?.split(',')[0] ||
           req.headers['x-real-ip'];
  }

  static detectSuspiciousActivity(req, user) {
    const currentIP = this.getClientIP(req);
    const currentUA = req.get('User-Agent');
    
    // Check for suspicious patterns
    const suspiciousPatterns = [
      !currentUA || currentUA.length < 10,
      currentIP === '127.0.0.1' && process.env.NODE_ENV === 'production',
      /bot|crawler|spider|scraper/i.test(currentUA)
    ];

    return suspiciousPatterns.some(pattern => pattern);
  }

  static createRateLimiter(windowMs, max, message) {
    return rateLimit({
      windowMs,
      max,
      message: { message },
      standardHeaders: true,
      legacyHeaders: false,
      handler: (req, res) => {
        this.logSecurityEvent(
          req.user?._id,
          'LOGIN_BLOCKED',
          `Rate limit exceeded from ${this.getClientIP(req)}`,
          req,
          'HIGH'
        );
        res.status(429).json({ message });
      }
    });
  }

  static createSlowDown(windowMs, delayAfter, delayMs) {
    return slowDown({
      windowMs,
      delayAfter,
      delayMs,
      maxDelayMs: delayMs * 10
    });
  }

  // Middleware for different endpoint protections
  static authLimiter = this.createRateLimiter(
    15 * 60 * 1000, // 15 minutes
    5, // limit each IP to 5 requests per windowMs
    'Too many authentication attempts, please try again later'
  );

  static otpLimiter = this.createRateLimiter(
    5 * 60 * 1000, // 5 minutes
    3, // limit each IP to 3 OTP requests per windowMs
    'Too many OTP requests, please try again later'
  );

  static adminLimiter = this.createRateLimiter(
    60 * 60 * 1000, // 1 hour
    10, // limit each IP to 10 admin requests per windowMs
    'Too many admin requests, please try again later'
  );

  static speedLimiter = this.createSlowDown(
    15 * 60 * 1000, // 15 minutes
    2, // slow down after 2 requests
    1000 // delay of 1 second
  );
}

module.exports = SecurityService;