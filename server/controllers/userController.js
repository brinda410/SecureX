import mongoose from "mongoose";
import User from "../models/User.js";

// =====================================================
// SECUREX USER CONTROLLER
// Profile Management + Encryption Key Management
// =====================================================

const KEY_ALGORITHM = "PBKDF2-SHA256";
const KEY_ITERATIONS = 600000;

// Validate Base64 input
const isValidBase64 = (value) => {
    if (typeof value !== "string" || value.length === 0) {
        return false;
    }

    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
        return false;
    }

    return Buffer.from(value, "base64").toString("base64") === value;
};

// Validate MongoDB ObjectId
const isValidUserId = (id) => {
    return mongoose.isValidObjectId(id);
};

// =====================================================
// 1. GET LOGGED-IN USER PROFILE
// GET /api/users/me
// =====================================================

export const getMyProfile = async (req, res) => {
    try {
        const user = await User.findById(req.user._id)
            .select("name email isOnline lastSeen createdAt publicKey keyVersion")
            .lean();

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        return res.status(200).json({
            success: true,
            user
        });

    } catch (error) {
        console.error("Profile retrieval failed:", error.message);

        return res.status(500).json({
            success: false,
            message: "Unable to retrieve profile"
        });
    }
};


// =====================================================
// 2. REGISTER ENCRYPTION KEYS
// POST /api/users/keys
//
// Existing encryption keys cannot be overwritten.
// =====================================================

export const saveEncryptionKeys = async (req, res) => {
    try {
        const {
            publicKey,
            encryptedPrivateKey,
            salt,
            iv
        } = req.body || {};

        // Validate required fields
        if (
            !publicKey ||
            !encryptedPrivateKey ||
            !salt ||
            !iv
        ) {
            return res.status(400).json({
                success: false,
                message: "All encryption key fields are required"
            });
        }

        // Validate field types
        if (
            typeof publicKey !== "string" ||
            typeof encryptedPrivateKey !== "string" ||
            typeof salt !== "string" ||
            typeof iv !== "string"
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid encryption key data"
            });
        }

        // Validate Base64 encoding
        if (
            !isValidBase64(publicKey) ||
            !isValidBase64(encryptedPrivateKey) ||
            !isValidBase64(salt) ||
            !isValidBase64(iv)
        ) {
            return res.status(400).json({
                success: false,
                message: "Encryption key data must use valid Base64 encoding"
            });
        }

        // Validate size limits
        if (
            publicKey.length > 2000 ||
            encryptedPrivateKey.length > 10000 ||
            salt.length > 100 ||
            iv.length > 100
        ) {
            return res.status(400).json({
                success: false,
                message: "Encryption key data exceeds allowed size"
            });
        }

        // Validate decoded cryptographic parameters
        const saltBuffer = Buffer.from(salt, "base64");
        const ivBuffer = Buffer.from(iv, "base64");
        const publicKeyBuffer = Buffer.from(publicKey, "base64");
        const encryptedKeyBuffer = Buffer.from(encryptedPrivateKey, "base64");

        if (
            saltBuffer.length !== 16 ||
            ivBuffer.length !== 12 ||
            publicKeyBuffer.length === 0 ||
            encryptedKeyBuffer.length < 16
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid encryption key parameters"
            });
        }

        // Atomically register keys only if no key material exists.
        // This prevents concurrent requests from replacing keys.
        const updatedUser = await User.findOneAndUpdate(
            {
                _id: req.user._id,

                $and: [
                    {
                        $or: [
                            { publicKey: null },
                            { publicKey: { $exists: false } }
                        ]
                    },
                    {
                        $or: [
                            { encryptedPrivateKey: null },
                            { encryptedPrivateKey: { $exists: false } }
                        ]
                    },
                    {
                        $or: [
                            { keySalt: null },
                            { keySalt: { $exists: false } }
                        ]
                    },
                    {
                        $or: [
                            { keyIV: null },
                            { keyIV: { $exists: false } }
                        ]
                    }
                ]
            },
            {
                $set: {
                    publicKey,
                    encryptedPrivateKey,
                    keySalt: salt,
                    keyIV: iv,
                    keyProtectionAlgorithm: KEY_ALGORITHM,
                    keyProtectionIterations: KEY_ITERATIONS
                }
            },
            {
                new: true,
                runValidators: true
            }
        );

        if (!updatedUser) {
            const existingUser = await User.findById(req.user._id)
                .select("_id")
                .lean();

            if (!existingUser) {
                return res.status(404).json({
                    success: false,
                    message: "User not found"
                });
            }

            return res.status(409).json({
                success: false,
                message: "Encryption keys are already registered. Key replacement is not permitted through this endpoint."
            });
        }

        return res.status(201).json({
            success: true,
            message: "Encryption keys registered successfully",
            keyVersion: updatedUser.keyVersion
        });

    } catch (error) {
        console.error("Encryption key registration failed:", error.message);

        return res.status(500).json({
            success: false,
            message: "Unable to register encryption keys"
        });
    }
};


// =====================================================
// 3. GET ANOTHER USER'S PUBLIC ENCRYPTION KEY
// GET /api/users/:userId/public-key
// =====================================================

export const getUserPublicKey = async (req, res) => {
    try {
        const { userId } = req.params;

        if (!isValidUserId(userId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid user ID"
            });
        }

        const user = await User.findById(userId)
            .select("name publicKey keyVersion")
            .lean();

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        if (!user.publicKey) {
            return res.status(404).json({
                success: false,
                message: "User has not registered an encryption key"
            });
        }

        return res.status(200).json({
            success: true,
            user: {
                id: user._id,
                name: user.name,
                publicKey: user.publicKey,
                keyVersion: user.keyVersion
            }
        });

    } catch (error) {
        console.error("Public key retrieval failed:", error.message);

        return res.status(500).json({
            success: false,
            message: "Unable to retrieve public key"
        });
    }
};


// =====================================================
// 4. GET LOGGED-IN USER'S ENCRYPTION KEYS
// GET /api/users/keys/me
//
// Only the authenticated user can retrieve their
// own encrypted private-key backup.
// =====================================================

export const getMyEncryptionKeys = async (req, res) => {
    try {
        const user = await User.findById(req.user._id)
            .select(
                "+encryptedPrivateKey +keySalt +keyIV"
            )
            .lean();

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        if (
            !user.publicKey ||
            !user.encryptedPrivateKey ||
            !user.keySalt ||
            !user.keyIV
        ) {
            return res.status(404).json({
                success: false,
                message: "Encryption keys are not registered"
            });
        }

        return res.status(200).json({
            success: true,

            keys: {
                publicKey: user.publicKey,

                encryptedPrivateKey: user.encryptedPrivateKey,

                salt: user.keySalt,

                iv: user.keyIV,

                algorithm: user.keyProtectionAlgorithm,

                iterations: user.keyProtectionIterations,

                keyVersion: user.keyVersion
            }
        });

    } catch (error) {
        console.error("Encryption key retrieval failed:", error.message);

        return res.status(500).json({
            success: false,
            message: "Unable to retrieve encryption keys"
        });
    }
};