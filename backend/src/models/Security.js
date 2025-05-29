const mongoose = require('mongoose');

const securityLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  action: {
    type: String,
    required: true,
    enum: [
   'LOGIN_SUCCESS',
      'LOGIN_FAILED',
      'LOGIN_BLOCKED',
      'PASSWORD_CHANGE',
      'ADMIN_CREATED',
      'DOCTOR_CREATED',
      'PATIENT_CREATED',
      'OTP_GENERATED',
      'OTP_VERIFIED',
      'OTP_FAILED',
      'ACCOUNT_LOCKED',
      'SUSPICIOUS_ACTIVITY'
    ]
  },
  details: String,
  ipAddress: String,
  userAgent: String,
  riskLevel: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    default: 'LOW'
  }
}, {
  timestamps: true
});

securityLogSchema.index({ userId: 1, createdAt: -1 });
securityLogSchema.index({ action: 1, createdAt: -1 });
securityLogSchema.index({ riskLevel: 1, createdAt: -1 });

module.exports = mongoose.model('SecurityLog', securityLogSchema);
