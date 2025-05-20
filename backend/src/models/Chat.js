const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    refPath: 'senderModel'  // Dynamic reference to either 'Patient', 'Doctor', or 'Specialist'
  },
  senderModel: {
    type: String,
    required: true,
    enum: ['Patient', 'Doctor', 'Specialist']
  },
  recipient: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    refPath: 'recipientModel'  // Dynamic reference like senderModel
  },
  recipientModel: {
    type: String,
    required: true,
    enum: ['Patient', 'Doctor', 'Specialist']
  },
  message: {
    type: String,
    required: true
  },
  read: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const chatSchema = new mongoose.Schema({
  participants: [{
    type: mongoose.Schema.Types.ObjectId,
    refPath: 'participantsModel',
    required: true
  }],
  participantsModel: {
    type: String,
    required: true,
    enum: ['Patient', 'Doctor', 'Specialist']
  },
  messages: [messageSchema]
}, { timestamps: true });

module.exports = mongoose.model('Chat', chatSchema);
