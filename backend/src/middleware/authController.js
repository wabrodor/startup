const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { setOtp, verifyOtp: verifyOtpUtil, deleteOtp } = require('../utils/otpStore');

// Utility: Create JWT
const createToken = (user) => {
  return jwt.sign(
    {
      id: user._id,
      role: user.role,
      linkedId: user.linkedId || null,
    },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
};

// Request OTP
const requestOtp = async (req, res, next) => {
  try {
    const { phone } = req.body;
    if (!phone) {
      const error = new Error('Phone number required');
      error.statusCode = 400;
      throw error;
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    setOtp(phone, otp);

    // TODO: integrate SMS gateway here for production
    console.log(`OTP for ${phone}: ${otp}`);

    res.json({ message: 'OTP sent successfully (dev only)', otp });
  } catch (err) {
    next(err);
  }
};

// Verify OTP
const verifyOtp = async (req, res, next) => {
  try {
    const { phone, otp } = req.body;

    if (!phone || !otp) {
      const error = new Error('Phone and OTP are required');
      error.statusCode = 400;
      throw error;
    }

    const validOtp = verifyOtpUtil(phone, otp);
    if (!validOtp) {
      const error = new Error('Invalid or expired OTP');
      error.statusCode = 400;
      throw error;
    }

    const user = await User.findOne({ phone });
    if (!user) {
      const error = new Error('User not found. Please contact clinic or admin.');
      error.statusCode = 404;
      throw error;
    }

    const token = createToken(user);
    deleteOtp(phone);

    res.json({
      token,
      user: {
        id: user._id,
        role: user.role,
        linkedId: user.linkedId || null,
      },
    });
  } catch (err) {
    next(err);
  }
};

module.exports = {
  requestOtp,
  verifyOtp,
};
