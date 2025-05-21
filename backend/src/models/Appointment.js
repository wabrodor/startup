
 const mongoose = require("mongoose")
 
const appointmentSchema = new mongoose.Schema({
  clinicId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Clinic',
  },
  patientId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Patient',
    required: true
  },
  Doctors: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Doctor',  // General practitioners are doctors in your schema
  },

  specialistId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Specialist',
    required: false
  },

    // 🔹 Booking Source
  createdByPatient: {
    type: Boolean,
    default: false // true if patient booked via app directly
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

    paymentId: {
    type: String // e.g., Razorpay or Stripe txn id
  },


}, { timestamps: true });

module.exports = mongoose.model('Appointment', appointmentSchema);
