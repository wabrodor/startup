/**
 * @swagger
 * /send-otp:
 *   post:
 *     summary: Request OTP for login
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - phone
 *             properties:
 *               phone:
 *                 type: string
 *                 example: "9876543210"
 *     responses:
 *       200:
 *         description: OTP sent successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 otp:
 *                   type: string
 *       400:
 *         description: Bad request, e.g. missing phone number
 */

/**
 * @swagger
 * /verify-otp:
 *   post:
 *     summary: Verify OTP and login
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - phone
 *               - otp
 *             properties:
 *               phone:
 *                 type: string
 *                 example: "9876543210"
 *               otp:
 *                 type: string
 *                 example: "123456"
 *     responses:
 *       200:
 *         description: Login successful with JWT token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     role:
 *                       type: string
 *                     linkedId:
 *                       type: string
 *       400:
 *         description: Invalid OTP or input
 *       404:
 *         description: User not found
 */



const express = require('express');
const router = express.Router();
const {verifyOtp, requestOtp }= require('../../middleware/authController');
const validatePhone = require('../../middleware/validatephone');
const  otpRateLimiter  = require('../../middleware/otpRateLimiter');
const asyncHandler = require('../../utils/asyncErrorHandler.js');

router.post('/send-otp', otpRateLimiter, validatePhone, asyncHandler(requestOtp));
router.post('/verify-otp', validatePhone, asyncHandler(verifyOtp));

module.exports = router;
