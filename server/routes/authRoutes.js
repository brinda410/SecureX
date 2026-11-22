import express from "express";

import {
  registerUser,
  loginUser,
  logoutUser
} from "../controllers/authController.js";

import protect from "../middleware/authMiddleware.js";

const router = express.Router();

// Register a new user
router.post("/register", registerUser);

// Login an existing user
router.post("/login", loginUser);

// Logout and invalidate existing JWT tokens
router.post("/logout", protect, logoutUser);

export default router;