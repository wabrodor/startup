const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  role: {
    type: String,
    enum: ['superAdmin', 'admin', 'patient', 'doctor', 'specialist'],
    required: true
  },

  email: {
    type: String,
    unique: true,
    sparse: true,
    lowercase: true,
    trim: true
  },

  phone: {
    type: String,
    unique: true,
    required: true,
    trim: true
  },

  passwordHash: {
    type: String,
  },

  // References to domain-specific profiles:
  patientId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Patient'
  },
  doctorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Doctor'
  },
  specialistId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Specialist'
  },

  isActive: {
    type: Boolean,
    default: true
  },

  lastLoginAt: {
    type: Date
  },

}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
