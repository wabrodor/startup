const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const OTP = require('../models/Otp');

class OTPService {
  static generateOTP() {
    return crypto.randomInt(100000, 999999).toString();
  }

  static async sendSMSOTP(phoneNumber, otp) {
    // Integrate with your SMS service (Twilio, AWS SNS, etc.)
    console.log(`Sending SMS OTP ${otp} to ${phoneNumber}`);
    
    // Example with Twilio (uncomment and configure)
    /*
    const twilio = require('twilio');
    const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN);
    
    try {
      await client.messages.create({
        body: `Your Patient Care System verification code is: ${otp}. Valid for 5 minutes. Never share this code.`,
        from: process.env.TWILIO_PHONE,
        to: phoneNumber
      });
      return true;
    } catch (error) {
      console.error('SMS sending failed:', error);
      return false;
    }
    */
    
    return true; // For development
  }static async createAndSendOTP(identifier, purpose = 'login', isEmail = false, ipAddress = '', userAgent = '') {
    try {
      // Check for rate limiting - max 3 OTPs per identifier per 15 minutes
      const recentOTPs = await OTP.countDocuments({
        identifier,
        createdAt: { $gt: new Date(Date.now() - 15 * 60 * 1000) }
      });

      if (recentOTPs >= 3) {
        return { success: false, message: 'Too many OTP requests. Please try again later.' };
      }

      const otp = this.generateOTP();
      const hashedOtp = await bcrypt.hash(otp, 10);

      // Invalidate existing OTPs for this identifier and purpose
      await OTP.updateMany(
        { identifier, purpose, isUsed: false },
        { isUsed: true }
      );

      // Create new OTP
      await OTP.create({
        identifier,
        otp: otp.substring(0, 2) + '****', // Store partial OTP for logs
        hashedOtp,
        purpose,
        ipAddress,
        userAgent
      });

      // Send OTP
      let sent = false;
      if (isEmail) {
        sent = await emailService.sendOTP(identifier, otp, purpose);
      } else {
        sent = await this.sendSMSOTP(identifier, otp);
      }

      return { success: sent, message: sent ? 'OTP sent successfully' : 'Failed to send OTP' };
    } catch (error) {
      console.error('Create and send OTP error:', error);
      return { success: false, message: 'Internal server error' };
    }
  }

  static async verifyOTP(identifier, otp, purpose = 'login') {
    try {
      const otpDoc = await OTP.findOne({
        identifier,
        purpose,
        isUsed: false,
        expiresAt: { $gt: new Date() }
      }).sort({ createdAt: -1 });

      if (!otpDoc) {
        return { success: false, message: 'Invalid or expired OTP' };
      }

      // Check attempts
      if (otpDoc.attempts >= 3) {
        otpDoc.isUsed = true;
        await otpDoc.save();
        return { success: false, message: 'Maximum OTP attempts exceeded' };
      }

      const isValid = await bcrypt.compare(otp, otpDoc.hashedOtp);
      
      if (isValid) {
        otpDoc.isUsed = true;
        await otpDoc.save();
        return { success: true, message: 'OTP verified successfully' };
      } else {
        otpDoc.attempts += 1;
        await otpDoc.save();
        return { 
          success: false, 
          message: `Invalid OTP. ${3 - otpDoc.attempts} attempts remaining` 
        };
      }
    } catch (error) {
      console.error('Verify OTP error:', error);
      return { success: false, message: 'Internal server error' };
    }
  }

  static async cleanupExpiredOTPs() {
    try {
      await OTP.deleteMany({
        $or: [
          { expiresAt: { $lt: new Date() } },
          { isUsed: true, createdAt: { $lt: new Date(Date.now() - 24 * 60 * 60 * 1000) } }
        ]
      });
      
    } catch (error) {
      console.error('OTP cleanup error:', error);
    }
  }
}

module.exports = OTPService;
