const nodemailer = require('nodemailer');

class EmailService {
  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT || 587,
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      },
      tls: {
        rejectUnauthorized: false
      }
    });
  }

  async sendOTP(email, otp, purpose = 'login') {
    const subject = this.getSubjectByPurpose(purpose);
    const html = this.getOTPTemplate(otp, purpose);

    try {
      await this.transporter.sendMail({
        from: `"Patient Care System" <${process.env.SMTP_FROM}>`,
        to: email,
        subject,
        html
      });
      return true;
    } catch (error) {
      console.error('Email sending failed:', error);
      return false;
    }
  }

  getSubjectByPurpose(purpose) {
    const subjects = {
      'login': 'Your Login Verification Code',
      'email_verification': 'Verify Your Email Address',
      'password_reset': 'Password Reset Code',
      'admin_verification': 'Admin Action Verification'
    };
    return subjects[purpose] || 'Verification Code';
  }

  getOTPTemplate(otp, purpose) {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verification Code</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; }
            .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
            .content { padding: 30px; }
            .otp-code { background: #f8f9fa; border: 2px dashed #007bff; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }
            .otp-number { font-size: 32px; font-weight: bold; color: #007bff; letter-spacing: 4px; }
            .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
            .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #6c757d; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🏥 Patient Care System</h1>
                <p>Secure Verification Code</p>
            </div>
            <div class="content">
                <h2>Your verification code is:</h2>
                <div class="otp-code">
                    <div class="otp-number">${otp}</div>
                </div>
                <p>This code will expire in <strong>5 minutes</strong> for security purposes.</p>
                <div class="warning">
                    <strong>⚠️ Security Notice:</strong> Never share this code with anyone. Our team will never ask for your verification code.
                </div>
                <p>If you didn't request this code, please ignore this email and contact our support team immediately.</p>
            </div>
            <div class="footer">
                <p>© ${new Date().getFullYear()} Patient Care System. All rights reserved.</p>
                <p>This is an automated message, please do not reply to this email.</p>
            </div>
        </div>
    </body>
    </html>
    `;
  }

  async sendWelcomeEmail(email, name, tempPassword, role) {
    const subject = `Welcome to Patient Care System - ${role.charAt(0).toUpperCase() + role.slice(1)} Account Created`;
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Welcome to Patient Care System</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; }
            .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; padding: 30px; text-align: center; }
            .content { padding: 30px; }
            .credentials { background: #f8f9fa; border-radius: 8px; padding: 20px; margin: 20px 0; }
            .temp-password { font-family: monospace; font-size: 18px; font-weight: bold; color: #dc3545; background: white; padding: 10px; border-radius: 4px; border: 1px solid #dee2e6; }
            .warning { background: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; margin: 20px 0; color: #721c24; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🏥 Welcome to Patient Care System</h1>
                <p>Your ${role} account has been created</p>
            </div>
            <div class="content">
                <h2>Hello ${name},</h2>
                <p>Your account has been successfully created in the Patient Care System.</p>
                
                <div class="credentials">
                    <h3>Your Login Credentials:</h3>
                    <p><strong>Role:</strong> ${role.charAt(0).toUpperCase() + role.slice(1)}</p>
                    <p><strong>Temporary Password:</strong></p>
                    <div class="temp-password">${tempPassword}</div>
                </div>

                <div class="warning">
                    <strong>🔒 Important Security Instructions:</strong>
                    <ul>
                        <li>This is a temporary password that must be changed on your first login</li>
                        <li>You will need to verify your identity with OTP during login</li>
                        <li>Never share your credentials with anyone</li>
                        <li>Choose a strong password with at least 8 characters including uppercase, lowercase, numbers, and special characters</li>
                    </ul>
                </div>

                <h3>Next Steps:</h3>
                <ol>
                    <li>Visit the Patient Care System login page</li>
                    <li>Enter your phone number and temporary password</li>
                    <li>Complete OTP verification</li>
                    <li>Set your new secure password</li>
                </ol>

                <p>If you have any questions or need assistance, please contact your system administrator.</p>
            </div>
            <div style="background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #6c757d;">
                <p>© ${new Date().getFullYear()} Patient Care System. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    `;

    try {
      await this.transporter.sendMail({
        from: `"Patient Care System" <${process.env.SMTP_FROM}>`,
        to: email,
        subject,
        html
      });
      return true;
    } catch (error) {
      console.error('Welcome email sending failed:', error);
      return false;
    }
  }
}
module.exports =  EmailService