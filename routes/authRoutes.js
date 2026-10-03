const express = require('express');
const router = express.Router();
const authController = require('../controllers/authControllers');
const auth = require('../middleware/auth');

router.post('/register', authController.registerUser);
router.post('/login', authController.loginUser);
router.post('/verify-otp', authController.verifyLoginOtp);

router.get('/google', authController.googleLogin);
router.get('/google/callback', authController.googleCallback);

router.get('/mfa/status', auth, authController.getMfaStatus);
router.get('/mfa/setup', auth, authController.setupMfa);
router.post('/mfa/setup', auth, authController.setupMfa);
router.post('/mfa/verify', auth, authController.verifyMfaSetup);

module.exports = router;
