const mongoose = require('mongoose');

const specialistSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String },
  phone: { type: String, required: true, unique: true },
  qualification: { type: String },
  experienceYears: { type: Number, default: 0 },
  consultingSince: { type: Date },

  
  earnings: {
    totalEarnings: {
      type: Number,
      default: 0   // Total all-time earnings
    },
    currentMonthEarnings: {
      type: Number,
      default: 0   // For dashboard or payout calculation
    },
    pendingPayout: {
      type: Number,
      default: 0   // Not yet paid to the specialist
    }
  },

  specialization: {
    type: String,
    enum: [
      'Cardiologist',
      'Endocrinologist',
      'Nephrologist',
      'Neurologist',
      'General Surgeon',
      'Pulmonologist',
      'Psychiatrist',
      'Dermatologist',
      'Other'
    ],
    required: true
  },
  isActive: { type: Boolean, default: true },

}, { timestamps: true });

module.exports = mongoose.model('Specialist', specialistSchema);
