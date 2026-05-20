const express = require('express');
const router = express.Router();
const {
  registerUser,
  loginUser,
  registerValidation,
  loginValidation,
} = require('../controllers/authController');

// POST /api/auth/register
router.post('/register', registerValidation, registerUser);

// POST /api/auth/login
router.post('/login', loginValidation, loginUser);

module.exports = router;
