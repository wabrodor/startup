const mongoose = require('mongoose');

const doctorSchema = new mongoose.Schema({
  clinicId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Clinic',
    required: true
  },
  name: { type: String, required: true },
  email: { type: String },
  phone: { type: String, required: true, unique: true },
  experienceYears: { type: Number, default: 0 },
  consultingSince: { type: Date },
  isActive: { type: Boolean, default: true },

  // Track when doctor was added/updated
}, { timestamps: true });

module.exports = mongoose.model('Doctor', doctorSchema);
