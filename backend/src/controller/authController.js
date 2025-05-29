// authController.js

const User = require('../models/User');
const OTP = require('../models/OTP');
const SecurityService = require('../utils/securityService');
const EmailService = require('../utils/emailService'); // Assuming you have an email service
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const {generateRefreshToken, generateToken} = require("../utils/tokenServices")
const generateTemporaryPassword = require("../utils/passwordGenerator")
const validatePhoneNumber = require("../utils/validators")

const authController = {
  /**
   * Send OTP to user's phone number

   */

  async sendOTP(req, res) {
  try {
    const { phoneNumber, purpose = 'login' } = req.body;

    // Validate phone number
    const { valid, message } = validatePhoneNumber(phoneNumber);
    if (!valid) {
      return res.status(400).json({ message });
    }

    // Check OTP request limit in last 15 minutes
    const otpLimitWindowMs = 15 * 60 * 1000;
    const maxOtpRequests = 3;

    const recentOTPs = await OTP.countDocuments({
      identifier: phoneNumber,
      createdAt: { $gt: new Date(Date.now() - otpLimitWindowMs) },
      purpose,
    });

    if (recentOTPs >= maxOtpRequests) {
      await SecurityService.logSecurityEvent(
        null,
        'OTP_LIMIT_EXCEEDED',
        `OTP limit exceeded for ${phoneNumber}`,
        req,
        'MEDIUM'
      );
      return res.status(429).json({ message: 'Too many OTP requests. Please try again later.' });
    }

    const userAgent = req.headers['user-agent'];
    const clientIP = SecurityService.getClientIP(req);

    // Create and send OTP
    const result = await OTP.createAndSendOTP(phoneNumber, purpose, false, clientIP, userAgent);

    // Log the event
    await SecurityService.logSecurityEvent(
      null,
      result.success ? 'OTP_GENERATED' : 'OTP_FAILED',
      `${purpose} OTP ${result.success ? 'sent' : 'failed'} for ${phoneNumber}`,
      req,
      result.success ? 'LOW' : 'MEDIUM'
    );

    return res.status(result.success ? 200 : 429).json({
      message: result.message,
      success: result.success,
    });
  } catch (error) {
    await SecurityService.logSecurityEvent(
      null,
      'OTP_ERROR',
      `OTP generation error: ${error.message}`,
      req,
      'HIGH'
    );
    return res.status(500).json({ message: 'Internal server error' });
  }
},


async  resendOTP(req, res) {
  try {
    const { phoneNumber, purpose = 'login' } = req.body;

    // Validate phone number
    const validation = validatePhoneNumber(phoneNumber);
    if (!validation.valid) {
      return res.status(400).json({ message: validation.message });
    }

    const userAgent = req.get('User-Agent');
    const clientIP = SecurityService.getClientIP(req);

    // ⏱️ Rate limit: max 3 OTPs in 15 min by phone + purpose
    const windowMs = 15 * 60 * 1000;
    const maxAttempts = 3;

    const recentOTPs = await OTP.countDocuments({
      identifier: phoneNumber,
      createdAt: { $gt: new Date(Date.now() - windowMs) },
      purpose
    });

    if (recentOTPs >= maxAttempts) {
      await SecurityService.logSecurityEvent(
        null,
        'OTP_RESEND_LIMIT_EXCEEDED',
        `Resend OTP limit exceeded for ${phoneNumber}`,
        req,
        'MEDIUM'
      );
      return res.status(429).json({ message: 'Too many OTP requests. Please try again later.' });
    }

    // 🧠 OPTIONAL: Rate-limit IP for spam prevention
    const recentIPAttempts = await OTP.countDocuments({
      ipAddress: clientIP,
      createdAt: { $gt: new Date(Date.now() - windowMs) },
      purpose
    });

    if (recentIPAttempts >= maxAttempts) {
      await SecurityService.logSecurityEvent(
        null,
        'OTP_IP_SPAM_BLOCKED',
        `Too many OTPs sent from IP ${clientIP}`,
        req,
        'HIGH'
      );
      return res.status(429).json({ message: 'Too many OTP attempts from this device. Try later.' });
    }

    // 🔍 Check if an unexpired OTP already exists
    const existingValidOTP = await OTP.findOne({
      identifier: phoneNumber,
      purpose,
      expiresAt: { $gt: new Date() }, // not expired
      isUsed: false
    });

    if (existingValidOTP) {
      await SecurityService.logSecurityEvent(
        null,
        'OTP_RESEND_BLOCKED_UNEXPIRED',
        `Resend blocked – unexpired OTP exists for ${phoneNumber}`,
        req,
        'LOW'
      );
      return res.status(400).json({
        message: 'An active OTP already exists. Please wait before requesting a new one.',
        expiresIn: Math.floor((existingValidOTP.expiresAt - new Date()) / 1000) // in seconds
      });
    }

    // 🔁 Create and send OTP
    const result = await OTP.createAndSendOTP(
      phoneNumber,
      purpose,
      false,
      clientIP,
      userAgent
    );

    await SecurityService.logSecurityEvent(
      null,
      result.success ? 'OTP_RESENT' : 'OTP_RESEND_FAILED',
      `OTP ${result.success ? 'resent' : 'resend failed'} for ${phoneNumber}`,
      req,
      result.success ? 'LOW' : 'MEDIUM'
    );

    return res.status(result.success ? 200 : 500).json({
      message: result.message,
      success: result.success
    });

  } catch (error) {
    await SecurityService.logSecurityEvent(
      null,
      'OTP_RESEND_ERROR',
      `Error while resending OTP: ${error.message}`,
      req,
      'HIGH'
    );
    return res.status(500).json({ message: 'Internal server error' });
  }
},

  async verifyOTP(req, res) {
    try {
      const { phoneNumber, otp } = req.body;
      
      if (!phoneNumber || !otp) {
        return res.status(400).json({ message: 'Phone number and OTP are required' });
      }

      const { success, message } = await OTP.verifyOTP(phoneNumber, otp);
      
      if (!success) {
        await SecurityService.logSecurityEvent(
          null, 
          'OTP_FAILED', 
          `OTP verification failed for ${phoneNumber}`, 
          req, 
          'MEDIUM'
        );
        return res.status(401).json({ message });
      }

      let user = await User.findOne({ phoneNumber });

      // if no user reject
      
 if (!user) {
  await SecurityService.logSecurityEvent(null, 'LOGIN_FAILED', `Login attempt with unregistered phone: ${phoneNumber}`, req, 'MEDIUM');
  return res.status(404).json({ message: 'Non-registered users cannot log in' });
}

      // Check if account is locked
      if (user.isAccountLocked()) {
        await SecurityService.logSecurityEvent(
          user._id, 
          'ACCOUNT_LOCKED', 
          'Account locked during OTP login', 
          req, 
          'HIGH'
        );
        return res.status(403).json({ message: 'Account is temporarily locked' });
      }


      // Detect suspicious activity
      if (SecurityService.detectSuspiciousActivity(req, user)) {
        await SecurityService.logSecurityEvent(
          user._id,
          'SUSPICIOUS_ACTIVITY',
          'Suspicious user agent or IP detected during OTP login',
          req,
          'CRITICAL'
        );
        // You might want to require additional verification here
      }

      // Create session and generate token
      const sessionToken = crypto.randomUUID();
      const token = authController.generateToken(user, sessionToken);
      const refreshToken =   authController.generateRefreshToken(user)

      await user.addSession(req.get('User-Agent'), SecurityService.getClientIP(req), sessionToken);
      await user.save();

      await SecurityService.logSecurityEvent(
        user._id, 
        'LOGIN_SUCCESS', 
        'User logged in with OTP', 
        req, 
        'LOW'
      );

      res.status(200).json({ 
        token, 
        refreshToken,
        user: { 
          id: user._id, 
          role: user.role, 
          phoneNumber: user.phoneNumber,
          requirePasswordChange: user.requirePasswordChange || false
        }
      });
    } catch (error) {
      await SecurityService.logSecurityEvent(
        null, 
        'LOGIN_ERROR', 
        `OTP verification error: ${error.message}`, 
        req, 
        'HIGH'
      );
      res.status(500).json({ message: 'Internal server error' });
    }
  },

  async refreshToken(req, res) {
  const { token } = req.body;
  if (!token) return res.status(400).json({ message: 'Refresh token required' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return res.status(401).json({ message: 'Invalid refresh token' });

    // Cleanup expired refresh tokens for this user
    await user.cleanupExpiredRefreshTokens();

    // Verify token is valid and not revoked
    if (!user.isRefreshTokenValid(token)) {
      await SecurityService.logSecurityEvent(user._id, 'REFRESH_TOKEN_INVALID', 'Refresh token invalid or revoked', req, 'HIGH');
      return res.status(401).json({ message: 'Refresh token invalid or expired' });
    }

    // Revoke old refresh token (rotate)
    user.revokeRefreshToken(token);

    // Generate new session token for access token
    const sessionToken = crypto.randomUUID();
    const accessToken = authController.generateToken(user, sessionToken);
    const newRefreshToken = authController.generateRefreshToken(user);

    // Store new refresh token hashed and expiry
    user.addRefreshToken(newRefreshToken);

    user.addSession(req.get('User-Agent'), SecurityService.getClientIP(req), sessionToken);
    await user.save();

    res.status(200).json({ token: accessToken, refreshToken: newRefreshToken });

  } catch (error) {
    console.error('Refresh token error:', error);
      await SecurityService.logSecurityEvent(
        null, 
        'LOGIN_ERROR', 
        `REFRESH TOKEN ERROR: ${error.message}`, 
        req, 
        'HIGH'
      );
    return res.status(401).json({ message: 'Invalid or expired refresh token' });
  }
},

  async createAdminAccount(req, res) {
    try {
      const { email, phoneNumber, name, tempPassword } = req.body;
      
      // Only superadmin can create admin accounts
      if (req.user.role !== 'superadmin') {
        return res.status(403).json({ message: 'Only superadmin can create admin accounts' });
      }

      // Check if user already exists
      const existingUser = await User.findOne({ $or: [{ email }, { phoneNumber }] });
      if (existingUser) {
        return res.status(400).json({ message: 'User with this email or phone number already exists' });
      }

      // Generate temporary password if not provided
      const temporaryPassword = tempPassword || this.generateTemporaryPassword();

      // Create admin user with temporary password flags
      const adminUser = await User.create({
        email,
        phoneNumber,
        name,
        password: temporaryPassword,
        role: 'admin',
        isTemporaryPassword: true,
        hasLoggedInBefore: false,
        passwordSetByAdmin: true,
        createdBy: req.user._id
      });

      await SecurityService.logSecurityEvent(
        req.user._id,
        'ADMIN_CREATED',
        `Admin account created for ${email}`,
        req,
        'MEDIUM'
      );

      // Send credentials to admin via email
      try {
        await EmailService.sendAdminCredentials(email, temporaryPassword, name);
        res.status(201).json({
          message: 'Admin account created successfully. Temporary credentials sent via email.',
          adminId: adminUser._id,
          tempPassword: temporaryPassword // Remove this in production - only for testing
        });
      } catch (emailError) {
        // If email fails, still return the password securely
        res.status(201).json({
          message: 'Admin account created but email failed to send.',
          adminId: adminUser._id,
          tempPassword: temporaryPassword,
          warning: 'Please provide credentials to admin manually'
        });
      }

    } catch (error) {
      await SecurityService.logSecurityEvent(
        req.user?._id,
        'ADMIN_CREATION_ERROR',
        `Failed to create admin account: ${error.message}`,
        req,
        'HIGH'
      );
      res.status(500).json({ message: 'Internal server error' });
    }
  },


  /**
   * Login with email and password (with 2FA)
  
   */
  async loginWithPassword(req, res) {
    try {
      const { email, password } = req.body;
      
      if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
      }

      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({ message: 'Invalid email format' });
      }

      const user = await User.findOne({ email }).select('+password');
      
      if (!user || !(await user.comparePassword(password))) {
        if (user) {
          await user.incrementLoginAttempts();
          await user.save();
        }
        await SecurityService.logSecurityEvent(
          user?._id, 
          'LOGIN_FAILED', 
          `Invalid login attempt for ${email}`, 
          req, 
          'MEDIUM'
        );
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Check if account is locked
      if (user.isAccountLocked()) {
        await SecurityService.logSecurityEvent(
          user._id, 
          'ACCOUNT_LOCKED', 
          'Account temporarily locked due to multiple failed logins', 
          req, 
          'HIGH'
        );
        return res.status(403).json({ 
          message: 'Account is temporarily locked due to multiple failed login attempts' 
        });
      }

      // Reset login attempts on successful password verification
      await user.resetLoginAttempts();

      // Check if this is an admin's first login with temp password
      if (user.role === 'admin' && (user.isTemporaryPassword || !user.hasLoggedInBefore)) {
        await SecurityService.logSecurityEvent(
          user._id, 
          'FIRST_TIME_LOGIN', 
          `Admin first-time login detected. TempPassword: ${user.isTemporaryPassword}, HasLoggedIn: ${user.hasLoggedInBefore}`, 
          req, 
          'MEDIUM'
        );
        
        // Generate session token for password change process
        const sessionToken = crypto.randomUUID();
        const tempToken = jwt.sign(
          { 
            id: user._id, 
            role: user.role, 
            sessionToken,
            tempPasswordLogin: true,
            firstTimeLogin: !user.hasLoggedInBefore
          },
          process.env.JWT_SECRET,
          { expiresIn: '30m' } // Short expiry for temp password
        );

        return res.status(200).json({
          message: user.isTemporaryPassword ? 'Password change required' : 'First-time login - password change recommended',
          tempToken,
          requirePasswordChange: true,
          userId: user._id,
          isFirstLogin: !user.hasLoggedInBefore
        });
      }

      // Send OTP for 2FA (for regular logins)
      if (!user.phoneNumber) {
        return res.status(400).json({ 
          message: 'Phone number not associated with account. Please contact support.' 
        });
      }

      const result = await OTP.createAndSendOTP(
        user.phoneNumber,
        '2fa-login',
        false,
        SecurityService.getClientIP(req),
        req.get('User-Agent')
      );

      await SecurityService.logSecurityEvent(
        user._id, 
        result.success ? 'OTP_GENERATED' : 'OTP_FAILED', 
        `2FA OTP ${result.success ? 'sent' : 'failed'} for ${user.email}`, 
        req, 
        result.success ? 'LOW' : 'MEDIUM'
      );

      if (!result.success) {
        return res.status(429).json({ message: result.message });
      }

      res.status(200).json({ 
        message: 'OTP sent for login verification', 
        tempUserId: user._id,
        phoneNumber: user.phoneNumber.replace(/(\d{3})\d{6}(\d{4})/, '$1******$2') // Mask phone number
      });
    } catch (error) {
      await SecurityService.logSecurityEvent(
        null, 
        'LOGIN_ERROR', 
        `Password login error: ${error.message}`, 
        req, 
        'HIGH'
      );
      res.status(500).json({ message: 'Internal server error' });
    }
  },

  /**
   * Verify 2FA OTP for password login
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async verifyLoginOTP(req, res) {
    try {
      const { tempUserId, otp } = req.body;
      
      if (!tempUserId || !otp) {
        return res.status(400).json({ message: 'User ID and OTP are required' });
      }

      const user = await User.findById(tempUserId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      const { success, message } = await OTP.verifyOTP(user.phoneNumber, otp, '2fa-login');
      
      if (!success) {
        await SecurityService.logSecurityEvent(
          user._id, 
          'OTP_FAILED', 
          '2FA OTP verification failed', 
          req, 
          'MEDIUM'
        );
        return res.status(401).json({ message });
      }

      // Detect suspicious activity
      if (SecurityService.detectSuspiciousActivity(req, user)) {
        await SecurityService.logSecurityEvent(
          user._id,
          'SUSPICIOUS_ACTIVITY',
          'Suspicious user agent or IP detected during 2FA login',
          req,
          'CRITICAL'
        );
        
          return res.status(403).json({
    message: 'Suspicious login attempt detected. Additional verification is required.',
    code: 'SECONDARY_VERIFICATION_REQUIRED',
  });
      }

      // Create session and generate token
      const sessionToken = crypto.randomUUID();
      const token = authController.generateToken(user, sessionToken);
      const refreshToken = authController.generateRefreshToken(user)
      await user.addSession(req.get('User-Agent'), SecurityService.getClientIP(req), sessionToken);
      await user.save();

      await SecurityService.logSecurityEvent(
        user._id, 
        'LOGIN_SUCCESS', 
        'User logged in after 2FA OTP verification', 
        req, 
        'LOW'
      );

      res.status(200).json({ 
        token, 
        refreshToken,
        user: { 
          id: user._id, 
          role: user.role, 
          email: user.email,
          requirePasswordChange: user.requirePasswordChange || false
        }
      });
    } catch (error) {
      await SecurityService.logSecurityEvent(
        null, 
        'LOGIN_ERROR', 
        `2FA OTP verification error: ${error.message}`, 
        req, 
        'HIGH'
      );
      res.status(500).json({ message: 'Internal server error' });
    }
  },

  /**
   * Change password for admin first-time login
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async changeTemporaryPassword(req, res) {
    try {
      const { newPassword, confirmPassword } = req.body;
      const userId = req.user.id;

      if (!newPassword || !confirmPassword) {
        return res.status(400).json({ message: 'New password and confirmation are required' });
      }

      if (newPassword !== confirmPassword) {
        return res.status(400).json({ message: 'Passwords do not match' });
      }

      // Password strength validation
      const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
      if (!passwordRegex.test(newPassword)) {
        return res.status(400).json({ 
          message: 'Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character' 
        });
      }

      const user = await User.findById(userId).select('+password');
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      // Verify this is indeed a temporary password scenario or first login
      if (!user.isTemporaryPassword && user.hasLoggedInBefore) {
        return res.status(400).json({ message: 'Password change not required' });
      }

      // Update password and remove temporary status
      user.password = newPassword;
      user.isTemporaryPassword = false;
      user.requirePasswordChange = false;
      user.hasLoggedInBefore = true;
      user.firstLoginAt = user.firstLoginAt || new Date();
      user.passwordChangedAt = new Date();
      await user.save();

      await SecurityService.logSecurityEvent(
        user._id, 
        'PASSWORD_CHANGED', 
        'Admin changed temporary password', 
        req, 
        'LOW'
      );

      // Generate new token without temp password flag
      const sessionToken = crypto.randomUUID();
      const token = authController.generateToken(user, sessionToken);
      
      await user.addSession(req.get('User-Agent'), SecurityService.getClientIP(req), sessionToken);
      await user.save();

      res.status(200).json({ 
        message: 'Password changed successfully',
        token,
        user: { 
          id: user._id, 
          role: user.role, 
          email: user.email,
          requirePasswordChange: false
        }
      });
    } catch (error) {
      await SecurityService.logSecurityEvent(
        req.user?.id, 
        'PASSWORD_CHANGE_ERROR', 
        `Password change error: ${error.message}`, 
        req, 
        'HIGH'
      );
      res.status(500).json({ message: 'Internal server error' });
    }
  },

  /**
   * Request password reset
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async requestPasswordReset(req, res) {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({ message: 'Email is required' });
      }

      const user = await User.findOne({ email });
      
      // Always return success to prevent email enumeration
      if (!user) {
        await SecurityService.logSecurityEvent(
          null, 
          'PASSWORD_RESET_ATTEMPT', 
          `Password reset attempted for non-existent email: ${email}`, 
          req, 
          'MEDIUM'
        );
        return res.status(200).json({ 
          message: 'If an account with that email exists, a password reset link has been sent' 
        });
      }

      // Generate reset token
      const resetToken = user.createPasswordResetToken();
      await user.save({ validateBeforeSave: false });

      // Create reset URL
      const resetURL = `${req.protocol}://${req.get('host')}/api/auth/reset-password/${resetToken}`;

      try {
        await EmailService.sendPasswordResetEmail(user.email, resetURL, user.name);
        
        await SecurityService.logSecurityEvent(
          user._id, 
          'PASSWORD_RESET_REQUESTED', 
          'Password reset email sent', 
          req, 
          'LOW'
        );

        res.status(200).json({ 
          message: 'Password reset link sent to your email' 
        });
      } catch (emailError) {
        // Reset the token if email fails
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save({ validateBeforeSave: false });

        await SecurityService.logSecurityEvent(
          user._id, 
          'PASSWORD_RESET_EMAIL_FAILED', 
          `Failed to send password reset email: ${emailError.message}`, 
          req, 
          'HIGH'
        );

        return res.status(500).json({ 
          message: 'Error sending password reset email. Please try again later.' 
        });
      }
    } catch (error) {
      await SecurityService.logSecurityEvent(
        null, 
        'PASSWORD_RESET_ERROR', 
        `Password reset request error: ${error.message}`, 
        req, 
        'HIGH'
      );
      res.status(500).json({ message: 'Internal server error' });
    }
  },

  /**
   * Reset password using token
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async resetPassword(req, res) {
    try {
      const { token } = req.params;
      const { password, confirmPassword } = req.body;

      if (!password || !confirmPassword) {
        return res.status(400).json({ message: 'Password and confirmation are required' });
      }

      if (password !== confirmPassword) {
        return res.status(400).json({ message: 'Passwords do not match' });
      }

      // Password strength validation
      const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
      if (!passwordRegex.test(password)) {
        return res.status(400).json({ 
          message: 'Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character' 
        });
      }

      // Hash the token and find user
      const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
      const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: { $gt: Date.now() }
      }).select('+password');

      if (!user) {
        await SecurityService.logSecurityEvent(
          null, 
          'PASSWORD_RESET_INVALID_TOKEN', 
          'Invalid or expired password reset token used', 
          req, 
          'MEDIUM'
        );
        return res.status(400).json({ message: 'Invalid or expired reset token' });
      }

      // Update password and clear reset token
      user.password = password;
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      user.passwordChangedAt = new Date();
      
      // Reset login attempts in case account was locked
      await user.resetLoginAttempts();
      await user.save();

      await SecurityService.logSecurityEvent(
        user._id, 
        'PASSWORD_RESET_SUCCESS', 
        'Password successfully reset using token', 
        req, 
        'LOW'
      );

      res.status(200).json({ 
        message: 'Password has been reset successfully. You can now log in with your new password.' 
      });
    } catch (error) {
      await SecurityService.logSecurityEvent(
        null, 
        'PASSWORD_RESET_ERROR', 
        `Password reset error: ${error.message}`, 
        req, 
        'HIGH'
      );
      res.status(500).json({ message: 'Internal server error' });
    }
  },

  /**
   * Logout user and invalidate session
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async logout(req, res) {
    try {
      const token = req.token;
       const refreshToken = req.body.refreshToken;
      const user = req.user;
      
   if (user) {
      if (accessToken) {
        await user.invalidateSession(accessToken);
      }
      if (refreshToken) {
        await user.revokeRefreshToken(refreshToken);
      }
      await user.save();

        
        await SecurityService.logSecurityEvent(
          user._id, 
          'LOGOUT', 
          'User logged out successfully', 
          req, 
          'LOW'
        );
      }

      res.status(200).json({ message: 'Logged out successfully' });
    } catch (error) {
      await SecurityService.logSecurityEvent(
        req.user?._id, 
        'LOGOUT_ERROR', 
        `Logout error: ${error.message}`, 
        req, 
        'MEDIUM'
      );
      res.status(500).json({ message: 'Error during logout' });
    }
  },
 
};

// Attach rate limiting middleware
const { authLimiter, otpLimiter, speedLimiter } = SecurityService;
authController.authLimiter = authLimiter;
authController.otpLimiter = otpLimiter;
authController.speedLimiter = speedLimiter;

module.exports = authController;