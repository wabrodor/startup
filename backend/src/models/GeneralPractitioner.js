const mongoose = require('mongoose');

const doctorSchema = new mongoose.Schema({
  name: { type: String, required: true },
  phone: { type: String, required: true, unique: true, trim: true },
  email: { type: String, lowercase: true, trim: true },

 
  specialization: {
  type: String,
  enum: [
   'Dietecian',  'Diabetologist', 'General Medicine'
  ],
  required: function () {
    return this.isPlatformDoctor === true;
  }, 
  default: null
},

  clinicId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Clinic',
    default: null // null for platform doctors
  },

  isPlatformDoctor: {
    type: Boolean,
    default: false
  },

  availableForChat: {
    type: Boolean,
    default: false
  },

  earnings: {
    totalEarned: { type: Number, default: 0 },
    lastPaymentDate: Date
  },

  active: { type: Boolean, default: true },
 
}, {timestamps: true},
)

// Custom logic to enforce consistency
doctorSchema.pre('save', function (next) {
  if (!this.isPlatformDoctor && !this.clinicId) {
    return next(new Error('Clinic doctors must have a clinicId'));
  }
  if (this.isPlatformDoctor) {
    this.clinicId = null;
     // Ensure platform doctors don't get linked accidentally
  }
  next();
});

module.exports = mongoose.model('Doctor', doctorSchema);
