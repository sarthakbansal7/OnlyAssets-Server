const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const authMiddleware = require('../middleware/authMiddleware');
const { adminOnly, issuerOnly, managerOnly, anyRole } = require('../middleware/roleMiddleware');

// Public routes
router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/verify-wallet', authController.verifyWallet);

// Protected routes (require authentication)
router.get('/profile', authMiddleware, authController.getProfile);
router.put('/profile', authMiddleware, authController.updateProfile);
router.post('/logout', authMiddleware, authController.logout);
router.get('/roles', authMiddleware, authController.getUserRoles);
router.post('/switch-role', authMiddleware, authController.switchRole);

// Admin-only routes
router.post('/admin/create-user', authMiddleware, adminOnly, authController.createUserByAdmin);

// Role-based route protection examples (these would be used by frontend route guards)
router.get('/admin/verify', authMiddleware, adminOnly, (req, res) => {
  res.json({ success: true, message: 'Admin access verified', role: 'admin' });
});

router.get('/issuer/verify', authMiddleware, issuerOnly, (req, res) => {
  res.json({ success: true, message: 'Issuer access verified', role: 'issuer' });
});

router.get('/manager/verify', authMiddleware, managerOnly, (req, res) => {
  res.json({ success: true, message: 'Manager access verified', role: 'manager' });
});

router.get('/dashboard/verify', authMiddleware, anyRole, (req, res) => {
  res.json({ success: true, message: 'Dashboard access verified', roles: req.userRoles });
});

// Health check route
router.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Auth service is running',
    timestamp: new Date().toISOString()
  });
});

module.exports = router;
