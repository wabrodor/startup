// seed.js
require('dotenv').config();
const mongoose = require('mongoose');

// Import your models (adjust paths if needed)
const User = require('./src/models/User');
const Clinic = require('./src/models/Clinic');
const Doctor = require('./src/models/GeneralPractitioner');
const Patient = require('./src/models/Patient');
const Specialist = require('./src/models/Specialist');

const {connectDB} = require("./src/config/db")

async function seed() {
  try {
    // Connect to DB
    await connectDB()
    console.log('✅ Connected to MongoDB');

    // Clear existing data (optional, be careful!)

 // Clear existing data (optional, be careful!)
    await User.deleteMany({});
    await Clinic.deleteMany({});
    await Doctor.deleteMany({});
    await Patient.deleteMany({});
    await Specialist.deleteMany({});

    // --- Super Admin ---
    const superAdmin = await User.create({
      phone: '9000000000',
      role: 'superAdmin',
      isActive: true,
    });

    // --- Clinic Admin ---
    const clinicAdmin = await User.create({
      phone: '9000000001',
      role: 'admin',
      isActive: true,
    });

    // --- Clinic ---
    const clinic = await Clinic.create({
      name: 'City Care Clinic',
      adminUser: clinicAdmin._id,
      phone: "90345678",
      address: {
        line1: '123 Main St',
        city: 'Metropolis',
        state: 'StateName',
        pincode: '123456',
      },
    });

    clinicAdmin.clinicId = clinic._id;
     await clinicAdmin.save();

    // --- Clinic Staff ---
    const staff1 = await User.create({
      phone: '9000000005',
      role: 'staff',
      isActive: true,
      name: "aliya",
      linkedClinic: clinic._id,
    });

    // --- Clinic Doctor ---
    const doctorProfile = await Doctor.create({
      name: 'Dr. Smith',
      phone: '9000000002',
      clinicId: clinic._id,
    });

    const doctorUser = await User.create({
      phone: doctorProfile.phone,
      role: 'doctor',
      doctorId: doctorProfile._id,
      isActive: true,
      linkedClinic: clinic._id,
    });

    // --- Platform Doctor (not linked to any clinic) ---
    const platformDoctorProfile = await Doctor.create({
      name: 'Dr. Platform',
      phone: '9000000003',
      specialization: 'General Medicine',
      isPlatformDoctor: true,
    });


    // --- Specialist (platform level) ---
    const specialistProfile = await Specialist.create({
      name: 'Dr. Specialist',
      phone: '9000000006',
      specialization: 'Endocrinologist',
    });

    const specialistUser = await User.create({
      phone: specialistProfile.phone,
      role: 'specialist',
      specialistId: specialistProfile._id,
      isActive: true,
    });

    // --- Patient linked to clinic doctor ---
    const patientProfile = await Patient.create({
    clinic: clinic._id, // Replace with real Clinic _id
  assignedDoctor: doctorProfile._id, // Replace with real Doctor _id
  platformDoctor: platformDoctorProfile._id, // Replace with real Platform Doctor _id

  name: {
    first: 'John',
    last: 'Doe'
  },
  gender: 'Male',
  dob: new Date('1980-06-15'),
  phone: '9876543210',
  email: 'john.doe@example.com',

  diseases: [
    {
      name: 'Hypertension',
      diagnosisDate: new Date('2022-05-10'),
      notes: 'Patient has been advised low sodium diet'
    },
    {
      name: 'Diabetes',
      diagnosisDate: new Date('2021-11-20'),
      notes: 'Monitoring HbA1c every 3 months'
    }
  ],

  labReports: [
    {
      title: 'HbA1c Report',
      fileUrl: 'https://example.com/lab/hba1c_report.pdf',
      date: new Date('2024-11-01')
    }
  ],

  ecgReports: [
    {
      fileUrl: 'https://example.com/ecg/ecg_report.pdf',
      date: new Date('2024-10-10'),
      notes: 'Normal sinus rhythm'
    }
  ],

  vitals: [
    {
      date: new Date(),
      grbs: 150,
      bloodPressure: { systolic: 140, diastolic: 90 },
      heartRate: 85,
      temperature: 98.6,
      respiratoryRate: 16,
      oxygenSaturation: 98,
      nextReminderDate: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000) // 5 days later
    }
  ],

  currentMedications: [
    {
      name: 'Metformin',
      dose: '500mg',
      frequency: 'Twice a day',
      startDate: new Date('2024-10-01')
    }
  ],

  pastMedications: [
    {
      name: 'Atenolol',
      dose: '50mg',
      frequency: 'Once daily',
      startDate: new Date('2023-05-01'),
      endDate: new Date('2024-01-01')
    }
  ],

  consultHistory: [
    {
      date: new Date('2025-05-01'),
      consultedWith: new mongoose.Types.ObjectId(), // Replace with GP/Specialist ID
      role: 'Doctor',
      notes: 'Follow-up on hypertension'
    }
  ],

  specialistReferrals: [
    {
      requestedBy: new mongoose.Types.ObjectId(), // Replace with doctor _id
      specialistType: 'Cardiologist',
      reason: 'Uncontrolled BP',
      dateRequested: new Date('2025-04-20'),
      status: 'pending'
    }
  ],

  nextSpecialistDue: new Date('2025-07-01'),

  notificationPreferences: {
    grbsReminder: {
      frequency: 'daily',
      enabled: true
    },
    bpReminder: {
      frequency: 'weekly',
      enabled: true
    }
  },

  registeredAt: new Date(),
})

    const patientUser = await User.create({
      phone: patientProfile.phone,
      role: 'patient',
      patientId: patientProfile._id,
      isActive: true,
    });

    console.log('🌱 Seed data created successfully!');
  } catch (err) {
    console.error('❌ Error seeding data:', err);
  } finally {
    await mongoose.connection.close();
    console.log('MongoDB connection closed.');
    process.exit(0);
  }
}

seed();
