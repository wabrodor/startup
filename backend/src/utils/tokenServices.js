const jwt = require('jsonwebtoken');

const generateToken = (user, sessionToken = null) => {
  const payload = {
    id: user._id,
    role: user.role,
    sessionToken,
    requirePasswordChange: user.requirePasswordChange || false
  };

  const options = {
  expiresIn: '1d',
  audience: process.env.JWT_AUDIENCE || 'your-app-users',
  issuer: process.env.JWT_ISSUER || 'your-app-name'
};

  return jwt.sign(payload, process.env.JWT_SECRET, options);
};

const generateRefreshToken = (user) => {
  return jwt.sign(
    { id: user._id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );
};

module.exports = {
  generateToken,
  generateRefreshToken
};
