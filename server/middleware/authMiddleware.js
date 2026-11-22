import jwt from "jsonwebtoken";

import User from "../models/User.js";
import Device from "../models/Device.js";

const JWT_ISSUER = "securex-api";
const JWT_AUDIENCE = "securex-client";

const protect = async (req, res, next) => {
    try {
        const authorization = req.headers.authorization;

        if (
            !authorization ||
            !authorization.startsWith("Bearer ")
        ) {
            return res.status(401).json({
                success: false,
                message: "Not authorized. Please log in."
            });
        }

        const token = authorization.slice(7).trim();
        const secret = process.env.JWT_SECRET;

        if (!token || !secret || secret.length < 32) {
            return res.status(401).json({
                success: false,
                message: "Invalid authentication configuration."
            });
        }

        const decoded = jwt.verify(token, secret, {
            algorithms: ["HS256"],
            issuer: JWT_ISSUER,
            audience: JWT_AUDIENCE
        });

        if (
            !decoded.id ||
            !decoded.deviceId ||
            !Number.isInteger(decoded.tokenVersion)
        ) {
            return res.status(401).json({
                success: false,
                message: "Invalid authentication token."
            });
        }

        const user = await User.findById(decoded.id).select(
            "-password -encryptedPrivateKey -keySalt -keyIV"
        );

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "User no longer exists."
            });
        }

        if (
            Number(user.tokenVersion || 0) !==
            decoded.tokenVersion
        ) {
            return res.status(401).json({
                success: false,
                message: "Session expired."
            });
        }

        const device = await Device.findOne({
            deviceId: decoded.deviceId,
            userId: user._id,
            revokedAt: null
        });

        if (!device) {
            return res.status(401).json({
                success: false,
                message: "This device session has been revoked."
            });
        }

        device.lastSeen = new Date();
        await device.save();

        req.user = user;
        req.deviceId = decoded.deviceId;

        return next();

    } catch (error) {
        return res.status(401).json({
            success: false,
            message: "Invalid or expired authentication token."
        });
    }
};

export default protect;