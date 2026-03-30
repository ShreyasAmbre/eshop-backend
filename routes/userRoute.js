import express from 'express';
import { changePassword, forgotPassword, allUsers, login, logout, register, reVerify, verify, verifyOtp, getUserById } from '../Controllers/userController.js';
import { isAuthenticated, isAdmin } from '../middleware/isAuthenticated.js';

const router = express.Router();

router.post('/register', register);
router.post('/verify', verify);
router.post('/reverify', reVerify);
router.post('/login', login);
router.post('/logout', isAuthenticated, logout);
router.post('/forgot-password', forgotPassword);
router.post('/verify-otp/:email', verifyOtp);
router.post('/change-password/:email', changePassword);
router.post('/all-users', isAuthenticated, isAdmin, allUsers);
router.post('/get-user/:userId', isAuthenticated, isAdmin, getUserById);

export default router
