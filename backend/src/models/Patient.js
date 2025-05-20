const mongoose = require('mongoose');

// Utility to calculate age
function calculateAge(dob) {
  const ageDifMs = Date.now() - dob.getTime();
  return Math.floor(ageDifMs / (1000 * 60 * 60 * 24 * 365.25));
}

const patientSchema = new mongoose.Schema({
  // 🔹 Clinic linkage
  clinic: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Clinic',
    required: true,
    index: true
  },

  // 🔹 Assigned Doctor & General Physician
  doctor: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Doctor',
    required: true
  },
  generalPhysician: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Specialist',
    required: true
  },

  // 🔹 Personal Information
  name: {
    first: { type: String, required: true },
    last: { type: String }
  },
  gender: {
    type: String,
    enum: ['Male', 'Female', 'Other'],
    required: true
  },
  dob: { type: Date, required: true },
  phone: { type: String, required: true, unique: true },
  email: { type: String },

  // 🔹 Diagnosed Diseases
  diseases: [{
    name: {
      type: String,
      enum: ['Hypertension', 'Diabetes'],
      required: true
    },
    diagnosisDate: Date,
    notes: String
  }],

  // 🔹 Lab & ECG Reports
  labReports: [{
    title: String,
    fileUrl: String,
    date: { type: Date, default: Date.now }
  }],
  ecgReports: [{
    fileUrl: String,
    date: { type: Date, default: Date.now },
    notes: String
  }],

  // 🔹 Vitals including GRBS and BP
  vitals: [{
    date: { type: Date, default: Date.now },
    grbs: Number,
    bloodPressure: {
      systolic: Number,
      diastolic: Number
    },
    heartRate: Number,
    temperature: Number,
    respiratoryRate: Number,
    oxygenSaturation: Number,
    nextReminderDate: Date
  }],

  // 🔹 Medications
  currentMedications: [{
    name: String,
    dose: String,
    frequency: String,
    startDate: Date
  }],
  pastMedications: [{
    name: String,
    dose: String,
    frequency: String,
    startDate: Date,
    endDate: Date
  }],

  // 🔹 Consult History (GP or Specialist)
  consultHistory: [{
    date: { type: Date, default: Date.now },
    consultedWith: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      refPath: 'consultHistory.role'
    },
    role: {
      type: String,
      required: true,
      enum: ['Doctor', 'Specialist']
    },
    notes: String
  }],

  // 🔹 Specialist Referrals
  specialistReferrals: [{
    requestedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Doctor',
      required: true
    },
    specialistType: {
      type: String,
      enum: [
        'Cardiologist', 'Endocrinologist', 'Nephrologist',
        'Pulmonologist', 'Diabetologist', 'Other'
      ],
      required: true
    },
    reason: String,
    dateRequested: { type: Date, default: Date.now },
    status: {
      type: String,
      enum: ['pending', 'accepted', 'rejected', 'completed'],
      default: 'pending'
    },
    consultedSpecialist: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Specialist'
    },
    consultDate: Date
  }],

  // 🔹 Specialist Review Reminder
  nextSpecialistDue: {
    type: Date
  },

  // 🔹 Notification Preferences
  notificationPreferences: {
    grbsReminder: {
      frequency: { type: String, enum: ['daily', 'weekly'], default: 'daily' },
      enabled: { type: Boolean, default: true }
    },
    bpReminder: {
      frequency: { type: String, enum: ['daily', 'weekly'], default: 'daily' },
      enabled: { type: Boolean, default: true }
    }
  },

  // 🔹 Misc
  registeredAt: { type: Date, default: Date.now }

}, { timestamps: true });

// Virtual: Age
patientSchema.virtual('age').get(function () {
  return calculateAge(this.dob);
});

// Move expired meds to past
patientSchema.pre('save', function (next) {
  if (!this.isModified('currentMedications')) return next();

  const now = new Date();
  const stillCurrent = [];

  this.currentMedications.forEach(med => {
    if (med.endDate && med.endDate < now) {
      this.pastMedications.push({ ...med.toObject(), endDate: med.endDate });
    } else {
      stillCurrent.push(med);
    }
  });

  this.currentMedications = stillCurrent;
  next();
});

// Filter index by phone
patientSchema.index({ phone: 1 });

module.exports = mongoose.model('Patient', patientSchema);
