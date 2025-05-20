// Subscription.js - boilerplate file for backend/src/modelsconst mongoose = require('mongoose');


const mongoose = require('mongoose');

const subscriptionSchema = new mongoose.Schema({
  clinicId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Clinic',
    required: true
  },

  planName: {
    type: String,
    required: true,
    trim: true
  },

  startDate: {
    type: Date,
    required: true,
    default: Date.now
  },

  endDate: {
    type: Date,
    required: true
  },

  isActive: {
    type: Boolean,
    default: true
  },

  paymentStatus: {
    type: String,
    enum: ['Pending', 'Paid', 'Failed', 'Cancelled'],
    default: 'Pending'
  },

  paymentMethod: {
    type: String,
    enum: ['Credit Card', 'Debit Card', 'UPI', 'Net Banking', 'Wallet', 'Cash'],
    required: false
  },

  autoRenew: {
    type: Boolean,
    default: false
  },

  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',  // Admin or superAdmin who created/managed subscription
    required: true
  }

}, { timestamps: true });

const subscription = mongoose.model('Subscription', subscriptionSchema);

const specialistEarningSchema = new mongoose.Schema({
  specialistId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Specialist',
    required: true
  },

  clinicId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Clinic',
    required: true
  },

  appointmentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Appointment',
    required: true
  },

  consultationFee: {
    type: Number,
    required: true,
    default: 500
  },

  specialistEarning: {
    type: Number,
    required: true,
    default: 350
  },

  clinicCut: {
    type: Number,
    required: true,
    default: 0   // 50 for premium, 0 for others
  },

  platformCut: {
    type: Number,
    required: true,
    default: 150  // derived from: 500 - 350 - clinicCut
  },

  clinicSubscriptionPlan: {
    type: String,
    enum: ['Free', 'Premium'],
    required: true
  },

  paymentStatus: {
    type: String,
    enum: ['Pending', 'Paid', 'Failed'],
    default: 'Pending'
  }

}, { timestamps: true });

const specialistEarning = mongoose.model('SpecialistEarning', specialistEarningSchema);

module.exports = {specialistEarning, subscription}
