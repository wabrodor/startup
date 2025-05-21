const validatePhone = (req, res, next) => {
  let { phone } = req.body;

  if (!phone) {
    return res.status(400).json({ error: 'Phone number is required' });
  }

  // Sanitize phone: remove all non-digit characters
  phone = phone.replace(/\D/g, '');

  // Validate phone length 10 digits
  if (phone.length !== 10) {
    return res.status(400).json({ error: 'Phone number must be exactly 10 digits' });
  }

  // Validate Indian mobile number format (starts with 6-9)
  const phoneRegex = /^[6-9]\d{9}$/;
  if (!phoneRegex.test(phone)) {
    return res.status(400).json({ error: 'Invalid phone number' });
  }

  req.body.phone = phone;
  next();
};

module.exports =  validatePhone