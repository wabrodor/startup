
const mongoose  = require("mongoose")

const clinicSchema = new mongoose.Schema({
  // 🔹 Basic Info
  name: { type: String, required: true },
  email: { type: String },
  phone: { type: String, required: true, unique: true },

  // 🔹 Address
  address: {
    line1: { type: String, required: true },
    line2: { type: String },
    city: { type: String, required: true },
    state: { type: String, required: true },
    pincode: { type: String, required: true },
    country: { type: String, default: 'India' }
  },

  // 🔹 Clinic Management
  adminUser: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  isActive: { type: Boolean, default: true },

  // 🔹 Subscription Plan
  subscriptionPlan: {
    planName: {
      type: String,
      enum: ['Free', 'Basic', 'Premium'],
      default: 'Free'
    },
    expiresAt: { type: Date }
  },

  // 🔹 Staff
  doctors: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Doctor'
  }],
  specialists: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Specialist'
  }],

  // 🔹 Patients
  patients: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Patient'
  }],

  // 🔹 Care Plans
  carePlans: [{
    title: String,
    description: String,
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Doctor'
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],

  // 🔹 Analytics (lightweight stats for dashboard)
  analytics: {
    totalPatients: { type: Number, default: 0 },
    totalConsults: { type: Number, default: 0 },
    pendingFollowUps: { type: Number, default: 0 },
    lastUpdated: { type: Date }
  },

  // 🔹 Specialist Consult Payment Settings
  paymentSettings: {
    enableSpecialistPayment: { type: Boolean, default: false },
    consultationFee: { type: Number, default: 0 }, // ₹ or $
    paymentGateway: { type: String } // e.g., Razorpay, Stripe
  }

}, { timestamps: true });

module.exports = mongoose.model('Clinic', clinicSchema);
