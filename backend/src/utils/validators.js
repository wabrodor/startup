// validators/phoneValidator.js

const indiaPhoneRegex = /^(?:\+91|0)?[6-9]\d{9}$/;

function validatePhoneNumber(phoneNumber) {
  if (!phoneNumber) {
    return { valid: false, message: 'Phone number is required' };
  }

  if (!indiaPhoneRegex.test(phoneNumber)) {
    return { valid: false, message: 'Invalid Indian phone number format' };
  }

  return { valid: true };
}

module.exports = {
  validatePhoneNumber,
};
