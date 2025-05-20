
 const mongoose = require("mongoose")
 
const appointmentSchema = new mongoose.Schema({
  clinicId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Clinic',
    required: true
  },
  patientId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Patient',
    required: true
  },
  generalPractitionerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Doctor',  // General practitioners are doctors in your schema
    required: true
  },
  specialistId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Specialist',
    required: false
  },

  appointmentDate: {
    type: Date,
    required: true
  },
  appointmentType: {
    type: String,
    enum: ['In-person', 'Teleconsultation'],
    default: 'In-person'
  },

  status: {
    type: String,
    enum: ['Scheduled', 'Completed', 'Cancelled', 'No-show'],
    default: 'Scheduled'
  },

  consultationNotes: { type: String }, // Doctor’s notes

  paymentStatus: {
    type: String,
    enum: ['Pending', 'Paid', 'Failed'],
    default: 'Pending'
  },
  paymentAmount: { type: Number, default: 0 },

  createdBy: {  // Who created the appointment (user id)
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }

}, { timestamps: true });

module.exports = mongoose.model('Appointment', appointmentSchema);
