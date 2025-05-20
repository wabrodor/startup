const mongoose = require('mongoose');

const payoutSchema = new mongoose.Schema({
  receiverType: {
    type: String,
    enum: ['Specialist', 'Clinic'],
    required: true
  },

  receiverId: {
    type: mongoose.Schema.Types.ObjectId,
    refPath: 'receiverType',
    required: true
  },

  amount: {
    type: Number,
    required: true
  },

  relatedEarningId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'SpecialistEarning' // or could be another Earning model
  },

  paymentMode: {
    type: String,
    enum: ['BankTransfer', 'UPI', 'Wallet', 'Manual'],
    required: true
  },

  status: {
    type: String,
    enum: ['Pending', 'Scheduled', 'Paid', 'Failed', 'Cancelled'],
    default: 'Pending'
  },

  transactionId: {
    type: String,
    unique: true,
    sparse: true // allow null until paid
  },

  scheduledDate: {
    type: Date
  },

  paidDate: {
    type: Date
  },

  failureReason: {
    type: String
  },

  notes: {
    type: String
  }

}, { timestamps: true });

module.exports = mongoose.model('Payout', payoutSchema);
