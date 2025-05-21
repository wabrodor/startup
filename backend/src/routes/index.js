const express = require('express');
const router = express.Router();

const authRoutes = require("./auth/authroute");           // 🔐 Auth
const tester =  require("./test")

router.use('/auth', authRoutes);
router.use ("/test", tester)
module.exports = router;
