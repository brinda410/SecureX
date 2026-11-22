import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { randomUUID } from "crypto";

import User from "../models/User.js";
import Device from "../models/Device.js";

const JWT_ISSUER = "securex-api";
const JWT_AUDIENCE = "securex-client";
const JWT_ALGORITHM = "HS256";

// ======================================================
// HELPERS
// ======================================================

const getJWTSecret = () => {
    const secret = process.env.JWT_SECRET;

    if (typeof secret !== "string" || secret.length < 32) {
        throw new Error("Invalid JWT configuration.");
    }

    return secret;
};

const isValidGmail = (email) =>
    /^[a-zA-Z0-9._%+-]+@gmail\.com$/i.test(email);

const createPublicUser = (user) => ({
    id: user._id,
    name: user.name,
    email: user.email
});

const createDeviceSession = async (user, req) => {
    const deviceId = randomUUID();

    const userAgent = String(
        req.headers["user-agent"] || ""
    ).slice(0, 500);

    const device = await Device.create({
        userId: user._id,
        deviceId,
        deviceName: userAgent.slice(0, 120) || "Unknown device",
        userAgent,
        ipAddress: String(req.ip || "").slice(0, 100),
        lastSeen: new Date()
    });

    const token = jwt.sign(
        {
            id: String(user._id),
            tokenVersion: Number(user.tokenVersion || 0),
            deviceId
        },
        getJWTSecret(),
        {
            algorithm: JWT_ALGORITHM,
            expiresIn: "1d",
            issuer: JWT_ISSUER,
            audience: JWT_AUDIENCE
        }
    );

    return { token, device };
};

// ======================================================
// REGISTER
// ======================================================

export const registerUser = async (req, res) => {
    try {
        const {
            name,
            email,
            password,
            confirmPassword
        } = req.body || {};

        if (
            typeof name !== "string" ||
            typeof email !== "string" ||
            typeof password !== "string" ||
            typeof confirmPassword !== "string"
        ) {
            return res.status(400).json({
                success: false,
                message: "Please fill in all fields correctly."
            });
        }

        const normalizedName = name.trim();
        const normalizedEmail = email.trim().toLowerCase();

        if (
            normalizedName.length < 2 ||
            normalizedName.length > 50 ||
            /[\u0000-\u001F\u007F]/.test(normalizedName)
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid name."
            });
        }

        if (!isValidGmail(normalizedEmail)) {
            return res.status(400).json({
                success: false,
                message: "Only valid Gmail addresses are allowed."
            });
        }

        if (
            password.length < 8 ||
            password.length > 128 ||
            Buffer.byteLength(password, "utf8") > 72
        ) {
            return res.status(400).json({
                success: false,
                message: "Password must contain 8–72 UTF-8 bytes."
            });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({
                success: false,
                message: "Passwords do not match."
            });
        }

        const existing = await User.findOne({
            email: normalizedEmail
        });

        if (existing) {
            return res.status(409).json({
                success: false,
                message: "Account already exists."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const user = await User.create({
            name: normalizedName,
            email: normalizedEmail,
            password: hashedPassword
        });

        const { token, device } =
            await createDeviceSession(user, req);

        return res.status(201).json({
            success: true,
            message: "Account created successfully.",
            token,
            user: createPublicUser(user),
            device: {
                deviceId: device.deviceId,
                deviceName: device.deviceName
            }
        });

    } catch (error) {
        if (error.code === 11000) {
            return res.status(409).json({
                success: false,
                message: "Account already exists."
            });
        }

        console.error("Registration error:", error.message);

        return res.status(500).json({
            success: false,
            message: "Registration failed."
        });
    }
};

// ======================================================
// LOGIN
// ======================================================

export const loginUser = async (req, res) => {
    try {
        const { email, password } = req.body || {};

        if (
            typeof email !== "string" ||
            typeof password !== "string" ||
            !email.trim() ||
            password.length > 128 ||
            Buffer.byteLength(password, "utf8") > 72
        ) {
            return res.status(400).json({
                success: false,
                message: "Enter your Gmail address and password."
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        if (!isValidGmail(normalizedEmail)) {
            return res.status(400).json({
                success: false,
                message: "Invalid Gmail address."
            });
        }

        const user = await User.findOne({
            email: normalizedEmail
        }).select("+password");

        if (!user || !user.password) {
            return res.status(401).json({
                success: false,
                message: "Invalid Gmail address or password."
            });
        }

        const validPassword = await bcrypt.compare(
            password,
            user.password
        );

        if (!validPassword) {
            return res.status(401).json({
                success: false,
                message: "Invalid Gmail address or password."
            });
        }

        const { token, device } =
            await createDeviceSession(user, req);

        return res.status(200).json({
            success: true,
            message: "Login successful.",
            token,
            user: createPublicUser(user),
            device: {
                deviceId: device.deviceId,
                deviceName: device.deviceName
            }
        });

    } catch (error) {
        console.error("Login error:", error.message);

        return res.status(500).json({
            success: false,
            message: "Login failed."
        });
    }
};

// ======================================================
// LOGOUT CURRENT DEVICE
// ======================================================

export const logoutUser = async (req, res) => {
    try {
        await Device.updateOne(
            {
                deviceId: req.deviceId,
                userId: req.user._id,
                revokedAt: null
            },
            {
                $set: {
                    revokedAt: new Date()
                }
            }
        );

        return res.status(200).json({
            success: true,
            message: "This device has been logged out."
        });

    } catch (error) {
        console.error("Logout error:", error.message);

        return res.status(500).json({
            success: false,
            message: "Unable to log out securely."
        });
    }
};
