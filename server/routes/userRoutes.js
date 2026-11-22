import express from "express";

import {
    getMyProfile,
    saveEncryptionKeys,
    getUserPublicKey,
    getMyEncryptionKeys
} from "../controllers/userController.js";

import protect from "../middleware/authMiddleware.js";

const router = express.Router();

// Get the authenticated user's profile
router.get("/me", protect, getMyProfile);

// Save the authenticated user's encryption keys
router.post("/keys", protect, saveEncryptionKeys);

// Get the authenticated user's encryption keys
router.get("/keys/me", protect, getMyEncryptionKeys);

// Get another user's public encryption key
router.get("/:userId/public-key", protect, getUserPublicKey);

export default router;