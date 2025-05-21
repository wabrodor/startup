// utils/otpStore.js
const otpStore = {};

const setOtp = (phone, otp) => {
  otpStore[phone] = {
    code: otp,
    expiresAt: Date.now() + 5 * 60 * 1000 // valid for 5 minutes
  };
};

const verifyOtp = (phone, otp) => {
  const record = otpStore[phone];
  if (!record) return false;
  if (Date.now() > record.expiresAt) return false;
  return record.code === otp;
};

const deleteOtp = (phone) => {
  delete otpStore[phone];
};

module.exports = { setOtp, verifyOtp, deleteOtp };
