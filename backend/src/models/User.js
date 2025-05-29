const mongoose = require('mongoose');
const crypto = require("crypto");
const bcrypt = require("bcryptjs");



const userSchema = new mongoose.Schema({
  phoneNumber: {
    type: String,
    required: true,
    unique: true,
    index: true,
    validate: {
      validator: function(v) {
        return /^[6-9]\d{9}$/.test(v);
      },
      message: 'Invalid mobile number format'
    }
  },
  email: {
    type: String,
    required: function() {
      return this.role === 'admin' || this.role === "superadmin";
    },
    unique: true,
    sparse: true,
    lowercase: true,
    validate: {
      validator: function(v) {
        return !v || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
      },
      message: 'Invalid email format'
    }
  },
  password: {
    type: String,
    required: function() {
      return this.role === 'admin';
    },
    minlength: 8,
    validate: {
      validator: function(v) {
        // Strong password: min 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char
        return !v || /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(v);
      },
      message: 'Password must contain at least 8 characters with uppercase, lowercase, number and special character'
    }
  },
  tempPassword: String,
  passwordHistory: [{
    password: String,
    createdAt: { type: Date, default: Date.now }
  }],
  role: {
    type: String,
    enum: ['admin', 'doctor', 'patient', 'superadmin', 'specialist'],
    required: true
  },
  isFirstLogin: {
    type: Boolean,
    default: true
  },
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },

  dateOfBirth: {
    type: Date,
    required: function() {
      return this.role === 'patient';
    },
    validate: {
      validator: function(v) {
        return !v || v < new Date();
      },
      message: 'Date of birth cannot be in the future'
    }
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastLoginAt: Date,
  loginAttempts: {
    type: Number,
    default: 0
  },
  refreshTokens: [
    {
   token: { type: String, required: true },        // the actual refresh token string
  issuedAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },      // expiration time
  revoked: { type: Boolean, default: false },     // revoked flag
  revokedAt: Date,
  replacedByToken: String
    }
   
],
  lockUntil: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  sessions: [{
    token: String,
    deviceInfo: String,
    ipAddress: String,
    createdAt: { type: Date, default: Date.now },
    expiresAt: Date,
    isActive: { type: Boolean, default: true }
  }],
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
 patientId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Patient'
  },
  doctorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Doctor'
  },
  specialistId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Specialist'
  },

    clinicId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Clinic'
    // Only set for: role = 'admin' or 'staff'
  },



}, {
  timestamps: true
});



// Virtual for account lock status
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});


// refresh token



userSchema.methods.addRefreshToken = function(rawToken, expiresInDays = 7) {
  const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');
  this.refreshTokens.push({
    token: hashedToken,
    expiresAt: new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000)
  });
};

userSchema.methods.isRefreshTokenValid = function(rawToken) {
  const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');
  return this.refreshTokens.some(rt =>
    rt.token === hashedToken && !rt.isRevoked && rt.expiresAt > new Date()
  );
};

userSchema.methods.revokeRefreshToken = function(rawToken) {
  const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');
  const tokenObj = this.refreshTokens.find(rt => rt.token === hashedToken);
  if (tokenObj) {
    tokenObj.isRevoked = true;
  }
};

userSchema.methods.cleanupExpiredRefreshTokens = async function() {
  const now = new Date();
  this.refreshTokens = this.refreshTokens.filter(rt => rt.expiresAt > now && !rt.isRevoked);
  await this.save();
};

// Pre-save middleware
userSchema.pre('save', async function(next) {
  // Hash password if modified
  if (this.isModified('password') && this.password) {
    // Check password history (last 5 passwords)
    if (this.passwordHistory && this.passwordHistory.length > 0) {
      for (let oldPassword of this.passwordHistory.slice(-5)) {
        if (await bcrypt.compare(this.password, oldPassword.password)) {
          throw new Error('Cannot reuse recent passwords');
        }
      }
    }
    
    const hashedPassword = await bcrypt.hash(this.password, 12);
    
    // Add to password history
    if (!this.passwordHistory) this.passwordHistory = [];
    this.passwordHistory.push({
      password: hashedPassword,
      createdAt: new Date()
    });
    
    // Keep only last 5 passwords
    if (this.passwordHistory.length > 5) {
      this.passwordHistory = this.passwordHistory.slice(-5);
    }
    
    this.password = hashedPassword;
  }
  
  // Hash temp password if modified
  if (this.isModified('tempPassword') && this.tempPassword) {
    this.tempPassword = await bcrypt.hash(this.tempPassword, 12);
  }
  
  next();
});

// Password comparison methods
userSchema.methods.comparePassword = async function(candidatePassword) {
  if (this.password) {
    return await bcrypt.compare(candidatePassword, this.password);
  }
  return false;
};

userSchema.methods.compareTempPassword = async function(candidatePassword) {
  if (this.tempPassword) {
    return await bcrypt.compare(candidatePassword, this.tempPassword);
  }
  return false;
};


// Login attempt methods
userSchema.methods.incrementLoginAttempts = async function() {
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + 30 * 60 * 1000 }; // 30 minutes
  }
  
  return this.updateOne(updates);
};


userSchema.methods.resetLoginAttempts = async function() {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 }
  });
};

// Password reset token
userSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  return resetToken;
};

// Session management
userSchema.methods.addSession = function(deviceInfo, ipAddress) {
  const sessionToken = crypto.randomBytes(32).toString('hex');
  const hashedToken = crypto.createHash('sha256').update(sessionToken).digest('hex');
  
  this.sessions.push({
    token: hashedToken,
    deviceInfo,
    ipAddress,
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
  });
  
  // Keep only last 3 active sessions
  if (this.sessions.length > 3) {
    this.sessions = this.sessions.slice(-3);
  }
  
  return sessionToken;
};

userSchema.methods.validateSession = function(sessionToken) {
  const hashedToken = crypto.createHash('sha256').update(sessionToken).digest('hex');
  const session = this.sessions.find(s => 
    s.token === hashedToken && 
    s.isActive && 
    s.expiresAt > new Date()
  );
  return !!session;
};

userSchema.methods.invalidateSession = function(sessionToken) {
  const hashedToken = crypto.createHash('sha256').update(sessionToken).digest('hex');
  const session = this.sessions.find(s => s.token === hashedToken);
  if (session) {
    session.isActive = false;
  }
};

// Indexes
userSchema.index({ email: 1 }, { unique: true, sparse: true });
userSchema.index({ role: 1, isActive: 1 });
userSchema.index({ passwordResetToken: 1 })

module. exports = mongoose.model("User", userSchema)
