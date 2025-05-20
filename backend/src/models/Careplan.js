const mongoose = require('mongoose');

const carePlanSchema = new mongoose.Schema({
  patientId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Patient',
    required: true,
    unique: true // One active care plan per patient
  },

  createdBy: {
    type: String,
    enum: ['Platform', 'Doctor', 'Specialist'],
    default: 'Platform'
  },

  assignedGP: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Doctor',
    required: true
  },

  specialistId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Specialist'
  },

  diagnosis: {
    type: [String],
    enum: ['Hypertension', 'Diabetes'],
    default: ['Hypertension', 'Diabetes']
  },

  goals: {
    type: String,
    default: 'Control BP < 130/80 mmHg and FBS < 110 mg/dL'
  },

  medications: [{
    name: String,
    dosage: String,
    frequency: String,
    startDate: {
      type: Date,
      default: Date.now
    },
    prescribedBy: {
      type: mongoose.Schema.Types.ObjectId,
      refPath: 'medications.prescribedByType'
    },
    prescribedByType: {
      type: String,
      enum: ['Doctor', 'Specialist']
    }
  }],

  lifestyleChanges: {
    type: String,
    default: 'Low salt diet, 30 min walking, reduced sugar'
  },

  followUpSchedule: {
    nextGPVisit: Date,
    nextSpecialistVisit: Date,
    nextLabTest: Date,
    nextECG: Date
  },

  notes: String,

  isActive: {
    type: Boolean,
    default: true
  }

}, { timestamps: true });

module.exports = mongoose.model('CarePlan', carePlanSchema);
