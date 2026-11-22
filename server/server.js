import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import mongoose from "mongoose";
import http from "http";
import jwt from "jsonwebtoken";
import helmet from "helmet";
import { rateLimit } from "express-rate-limit";
import { RedisStore } from "rate-limit-redis";
import { Server } from "socket.io";
import { createAdapter } from "@socket.io/redis-adapter";
import multer from "multer";
import securityRoutes from "./routes/securityRoutes.js";

import {
    getRedisClient,
    getRedisPubSubClients,
    connectRedis,
    closeRedis
} from "./config/redis.js";

import {
    checkSocketRateLimit
} from "./middleware/socketRateLimiter.js";

import {
    addSocketPresence,
    removeSocketPresence
} from "./services/presenceService.js";

import {
    recordThreat
} from "./services/playCipherService.js";

import User from "./models/User.js";
import Device from "./models/Device.js";
import Conversation from "./models/Conversation.js";
import Message from "./models/Message.js";

import authRoutes from "./routes/authRoutes.js";
import userRoutes from "./routes/userRoutes.js";
import deviceRoutes from "./routes/deviceRoutes.js";
import conversationRoutes from "./routes/conversationRoutes.js";
import messageRoutes from "./routes/messageRoutes.js";
import groupKeyRoutes from "./routes/groupKeyRoutes.js";

dotenv.config();

// ==========================================
// 1. APPLICATION INITIALIZATION
// ==========================================

const app = express();
const server = http.createServer(app);
// Trust the single Nginx reverse proxy
app.set("trust proxy", 1);
const JWT_ISSUER = "securex-api";
const JWT_AUDIENCE = "securex-client";

const redis = getRedisClient();

app.disable("x-powered-by");

// ==========================================
// 2. CORS CONFIGURATION
// ==========================================

const allowedOrigins = [
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",

    ...(process.env.CLIENT_URL || "")
        .split(",")
        .map(origin => origin.trim().replace(/\/$/, ""))
        .filter(Boolean)
];
const corsOptions = {
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            return callback(null, true);
        }

        return callback(
            new Error("Origin not allowed by SecureX CORS")
        );
    },

    credentials: true,

    methods: [
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS"
    ],

    allowedHeaders: [
        "Content-Type",
        "Authorization"
    ],

    exposedHeaders: [
        "RateLimit",
        "RateLimit-Policy",
        "Retry-After"
    ]
};

app.use(cors(corsOptions));

// ==========================================
// 3. SECURITY HEADERS
// ==========================================

app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                frameAncestors: ["'none'"],
                objectSrc: ["'none'"],
                upgradeInsecureRequests: null
            }
        }
    })
);

// ==========================================
// 4. BODY PARSING
// ==========================================

app.use(express.json({
    limit: "10mb"
}));

app.use(express.urlencoded({
    extended: false,
    limit: "1mb"
}));

// ==========================================
// 5. NOSQL INJECTION PROTECTION
// ==========================================

function containsUnsafeMongoKeys(value) {
    if (value === null || typeof value !== "object") {
        return false;
    }

    if (Array.isArray(value)) {
        return value.some(containsUnsafeMongoKeys);
    }

    for (const [key, nestedValue] of Object.entries(value)) {
        if (key.startsWith("$") || key.includes(".")) {
            return true;
        }

        if (containsUnsafeMongoKeys(nestedValue)) {
            return true;
        }
    }

    return false;
}

app.use((req, res, next) => {
    try {
        const unsafeBody = containsUnsafeMongoKeys(req.body);
        const unsafeQuery = containsUnsafeMongoKeys(req.query);

        if (unsafeBody || unsafeQuery) {
            void recordThreat({
                type: "NOSQL_INJECTION",
                severity: "CRITICAL",
                source: "HTTP",
                userId: null,
                ipAddress: req.ip,
                method: req.method,
                endpoint: req.path,
                description: "Potential NoSQL injection attempt blocked."
            });

            return res.status(400).json({
                success: false,
                message: "Invalid request data."
            });
        }

        next();

    } catch (error) {
        console.error(
            "[PLAYCIPHER INSPECTION ERROR]",
            error.message
        );

        return res.status(400).json({
            success: false,
            message: "Invalid request data."
        });
    }
});

// ==========================================
// 6. PLAYCIPHER SUSPICIOUS REQUEST DETECTION
// ==========================================

const suspiciousPatterns =
    /(\$where|\$gt|\$ne|\$regex|<script|javascript:|union\s+select|\/etc\/passwd|%3cscript)/i;

app.use((req, res, next) => {
    try {
        const requestTarget =
            `${req.originalUrl} ${JSON.stringify(req.query)}`;

        if (suspiciousPatterns.test(requestTarget)) {
            void recordThreat({
                type: "SUSPICIOUS_REQUEST",
                severity: "HIGH",
                source: "HTTP",
                userId: null,
                ipAddress: req.ip,
                method: req.method,
                endpoint: req.path,
                description: "Suspicious request pattern detected."
            });
        }

        next();

    } catch (error) {
        console.error(
            "[PLAYCIPHER REQUEST INSPECTION ERROR]",
            error.message
        );

        next();
    }
});

// ==========================================
// 7. GENERAL API RATE LIMITER - REDIS
// ==========================================

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,

    limit: process.env.NODE_ENV === "production"
        ? 3000
        : 10000,

    standardHeaders: "draft-8",
    legacyHeaders: false,

    store: new RedisStore({
        sendCommand: (command, ...args) =>
            redis.call(command, ...args),

        prefix: "securex:rl:general:"
    }),

    handler: (req, res) => {
        void recordThreat({
            type: "API_RATE_LIMIT",
            severity: "MEDIUM",
            source: "HTTP",
            userId: null,
            ipAddress: req.ip,
            method: req.method,
            endpoint: req.path,
            description: "General API rate limit exceeded."
        });

        return res.status(429).json({
            success: false,
            message: "Too many requests. Please try again later."
        });
    }
});

app.use("/api", generalLimiter);

// ==========================================
// 8. AUTHENTICATION RATE LIMITER - REDIS
// ==========================================

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,

    limit: process.env.NODE_ENV === "production"
        ? 30
        : 100,

    standardHeaders: "draft-8",
    legacyHeaders: false,

    store: new RedisStore({
        sendCommand: (command, ...args) =>
            redis.call(command, ...args),

        prefix: "securex:rl:auth:"
    }),

    handler: (req, res) => {
        void recordThreat({
            type: "AUTH_RATE_LIMIT",
            severity: "HIGH",
            source: "AUTH",
            userId: null,
            ipAddress: req.ip,
            method: req.method,
            endpoint: req.path,
            description: "Authentication rate limit exceeded."
        });

        return res.status(429).json({
            success: false,
            message: "Too many authentication attempts. Please try again later."
        });
    }
});

// ==========================================
// 9. SOCKET.IO INITIALIZATION
// ==========================================

const io = new Server(server, {
    cors: corsOptions
});

app.set("io", io);

// ==========================================
// 10. HEALTH CHECK
// ==========================================

app.get("/", (req, res) => {
    res.json({
        success: true,
        message: "SecureX API is running!",
        security: "Enabled",
        playCipher: "Enabled"
    });
});

// ==========================================
// 11. API ROUTES
// ==========================================

app.use("/api/auth", authLimiter, authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/devices", deviceRoutes);
app.use("/api/conversations", conversationRoutes);
app.use("/api/messages", messageRoutes);
app.use("/api/group-keys", groupKeyRoutes);
app.use("/api/security", securityRoutes);


// ==========================================
// 12. API NOT FOUND
// ==========================================

app.use("/api", (req, res) => {
    res.status(404).json({
        success: false,
        message: "API endpoint not found"
    });
});

// ==========================================
// 13. GLOBAL ERROR HANDLER
// ==========================================

app.use((error, req, res, next) => {
    console.error("[SECUREX ERROR]", {
        message: error.message,
        method: req.method,
        path: req.path,
        timestamp: new Date().toISOString()
    });

    if (res.headersSent) {
        return next(error);
    }

    if (
        error.message ===
        "Origin not allowed by SecureX CORS"
    ) {
        return res.status(403).json({
            success: false,
            message: "Request origin not allowed."
        });
    }

    if (error.code === "LIMIT_FILE_SIZE") {
        return res.status(413).json({
            success: false,
            message: "Encrypted attachment exceeds the 26 MB limit."
        });
    }

    if (error instanceof multer.MulterError) {
        return res.status(400).json({
            success: false,
            message: "Invalid attachment upload."
        });
    }

    return res.status(
        error.status && error.status < 500
            ? error.status
            : 500
    ).json({
        success: false,
        message:
            error.status && error.status < 500
                ? error.message
                : "Internal server error."
    });
});

// ==========================================
// 14. SOCKET AUTHENTICATION
// DEVICE SESSION VALIDATION
// ==========================================

io.use(async (socket, next) => {
    try {
        const token = socket.handshake.auth?.token;

        if (!token) {
            return next(new Error("Authentication required"));
        }

        const secret = process.env.JWT_SECRET;

        if (!secret || secret.length < 32) {
            return next(
                new Error("Authentication configuration error")
            );
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
            return next(
                new Error("Invalid authentication token")
            );
        }

        const user = await User.findById(decoded.id).select(
            "-password -encryptedPrivateKey -keySalt -keyIV"
        );

        if (!user) {
            return next(new Error("User not found"));
        }

        if (
            Number(user.tokenVersion || 0) !==
            decoded.tokenVersion
        ) {
            return next(
                new Error("Session expired. Please log in again.")
            );
        }

        const device = await Device.findOne({
            deviceId: decoded.deviceId,
            userId: user._id,
            revokedAt: null
        });

        if (!device) {
            return next(
                new Error("Device session revoked or not found.")
            );
        }

        device.lastSeen = new Date();
        await device.save();

        socket.user = user;
        socket.deviceId = decoded.deviceId;

        next();

    } catch (error) {
        void recordThreat({
            type: "INVALID_SOCKET_AUTH",
            severity: "HIGH",
            source: "SOCKET",
            userId: null,
            ipAddress: socket.handshake.address,
            endpoint: "socket_authentication",
            description: "Socket authentication failed.",
            metadata: {
                reason: String(error.message).slice(0, 200)
            }
        });

        console.error(
            "[SOCKET AUTH ERROR]",
            error.message
        );

        next(new Error("Invalid or expired socket token"));
    }
});

// ==========================================
// 15. SOCKET HELPERS AND RATE LIMITING
// ==========================================

function isValidId(id) {
    return (
        typeof id === "string" &&
        mongoose.Types.ObjectId.isValid(id)
    );
}

async function allowSocketEvent(
    socket,
    eventName,
    limit,
    interval
) {
    try {
        const result = await checkSocketRateLimit({
            userId: socket.user._id.toString(),
            eventName,
            limit,
            windowMs: interval
        });

        if (!result.allowed) {
            void recordThreat({
                type: "SOCKET_RATE_LIMIT",
                severity: "MEDIUM",
                source: "SOCKET",
                userId: socket.user._id,
                ipAddress: socket.handshake.address,
                endpoint: eventName,
                description: "Socket event rate limit exceeded.",
                metadata: {
                    event: eventName,
                    retryAfterMs: result.retryAfterMs
                }
            });

            return false;
        }

        return true;

    } catch (error) {
        console.error(
            "[SOCKET RATE LIMIT ERROR]",
            error.message
        );

        return false;
    }
}

async function isConversationMember(
    conversationId,
    userId
) {
    if (!isValidId(conversationId)) {
        return false;
    }

    const conversation = await Conversation.findOne({
        _id: conversationId,
        participants: userId
    }).select("_id");

    return Boolean(conversation);
}

async function verifyConversationAccess(
    socket,
    conversationId
) {
    const room = `conversation:${conversationId}`;

    if (!socket.rooms.has(room)) {
        return false;
    }

    const isMember = await isConversationMember(
        conversationId,
        socket.user._id
    );

    if (!isMember) {
        await socket.leave(room);
        return false;
    }

    return true;
}

// ==========================================
// 16. SOCKET EVENTS AND REDIS PRESENCE
// ==========================================

io.on("connection", (socket) => {
    const userId = socket.user._id.toString();
    const deviceId = socket.deviceId;

    console.log(
        "SecureX authenticated socket:",
        userId,
        "Device:",
        deviceId
    );

    socket.join(`user:${userId}`);
    socket.join(`device:${deviceId}`);

    // ======================================
    // REDIS ONLINE PRESENCE
    // ======================================

    let presenceHeartbeat = null;

    const presenceReady = addSocketPresence(
        userId,
        socket.id
    ).then((connectionCount) => {
        if (socket.connected && connectionCount === 1) {
            io.emit("user_online", { userId });
        }

        return connectionCount;

    }).catch((error) => {
        console.error(
            "[PRESENCE REGISTER ERROR]",
            error.message
        );

        throw error;
    });

    presenceReady.then(() => {
        if (!socket.connected) {
            return;
        }

        presenceHeartbeat = setInterval(async () => {
            if (!socket.connected) {
                return;
            }

            try {
                await addSocketPresence(
                    userId,
                    socket.id
                );

            } catch (error) {
                console.error(
                    "[PRESENCE HEARTBEAT ERROR]",
                    error.message
                );
            }

        }, 20 * 1000);

        presenceHeartbeat.unref?.();

    }).catch(() => {});

    // ======================================
    // JOIN CONVERSATION
    // ======================================

    socket.on(
        "join_conversation",
        async (conversationId, callback) => {
            try {
                if (
                    !(await allowSocketEvent(
                        socket,
                        "join_conversation",
                        30,
                        60000
                    ))
                ) {
                    if (typeof callback === "function") {
                        callback({
                            success: false,
                            message: "Too many join requests."
                        });
                    }

                    return;
                }

                if (!isValidId(conversationId)) {
                    if (typeof callback === "function") {
                        callback({
                            success: false,
                            message: "Invalid conversation ID."
                        });
                    }

                    return;
                }

                const isMember = await isConversationMember(
                    conversationId,
                    socket.user._id
                );

                if (!isMember) {
                    if (typeof callback === "function") {
                        callback({
                            success: false,
                            message: "You are not a member of this conversation."
                        });
                    }

                    return;
                }

                await socket.join(
                    `conversation:${conversationId}`
                );

                if (typeof callback === "function") {
                    callback({
                        success: true,
                        message: "Joined conversation successfully."
                    });
                }

            } catch (error) {
                console.error(
                    "JOIN CONVERSATION ERROR:",
                    error.message
                );

                if (typeof callback === "function") {
                    callback({
                        success: false,
                        message: "Unable to join conversation."
                    });
                }
            }
        }
    );

    // ======================================
    // LEAVE CONVERSATION
    // ======================================

    socket.on(
        "leave_conversation",
        async (conversationId) => {
            try {
                if (!isValidId(conversationId)) {
                    return;
                }

                await socket.leave(
                    `conversation:${conversationId}`
                );

            } catch (error) {
                console.error(
                    "LEAVE CONVERSATION ERROR:",
                    error.message
                );
            }
        }
    );

    // ======================================
    // TYPING
    // ======================================

    socket.on("typing", async (conversationId) => {
        try {
            if (
                !(await allowSocketEvent(
                    socket,
                    "typing",
                    30,
                    10000
                ))
            ) {
                return;
            }

            if (!isValidId(conversationId)) {
                return;
            }

            const hasAccess = await verifyConversationAccess(
                socket,
                conversationId
            );

            if (!hasAccess) {
                return;
            }

            socket.to(
                `conversation:${conversationId}`
            ).emit("user_typing", {
                conversationId,
                userId
            });

        } catch (error) {
            console.error("TYPING ERROR:", error.message);
        }
    });

    // ======================================
    // STOP TYPING
    // ======================================

    socket.on(
        "stop_typing",
        async (conversationId) => {
            try {
                if (
                    !(await allowSocketEvent(
                        socket,
                        "typing",
                        30,
                        10000
                    ))
                ) {
                    return;
                }

                if (!isValidId(conversationId)) {
                    return;
                }

                const hasAccess = await verifyConversationAccess(
                    socket,
                    conversationId
                );

                if (!hasAccess) {
                    return;
                }

                socket.to(
                    `conversation:${conversationId}`
                ).emit("user_stop_typing", {
                    conversationId,
                    userId
                });

            } catch (error) {
                console.error(
                    "STOP TYPING ERROR:",
                    error.message
                );
            }
        }
    );

    // ======================================
    // MESSAGE DELIVERED
    // ======================================

    socket.on(
        "message_delivered",
        async (payload) => {
            try {
                if (
                    !(await allowSocketEvent(
                        socket,
                        "message_delivered",
                        120,
                        60000
                    ))
                ) {
                    return;
                }

                const {
                    conversationId,
                    messageId
                } = payload || {};

                if (
                    !isValidId(conversationId) ||
                    !isValidId(messageId)
                ) {
                    return;
                }

                const hasAccess = await verifyConversationAccess(
                    socket,
                    conversationId
                );

                if (!hasAccess) {
                    return;
                }

                const message = await Message.findOne({
                    _id: messageId,
                    conversationId,
                    sender: {
                        $ne: socket.user._id
                    }
                });

                if (!message) {
                    return;
                }

                if (message.deliveryStatus !== "read") {
                    message.deliveryStatus = "delivered";
                    message.deliveredAt = new Date();

                    await message.save();
                }

                io.to(
                    `conversation:${conversationId}`
                ).emit("message_status_updated", {
                    conversationId,
                    messageId,
                    userId,
                    deliveryStatus: message.deliveryStatus,
                    deliveredAt: message.deliveredAt,
                    readAt: message.readAt
                });

            } catch (error) {
                console.error(
                    "MESSAGE DELIVERED ERROR:",
                    error.message
                );
            }
        }
    );

    // ======================================
    // MESSAGE READ
    // ======================================

    socket.on(
        "message_read",
        async (payload) => {
            try {
                if (
                    !(await allowSocketEvent(
                        socket,
                        "message_read",
                        120,
                        60000
                    ))
                ) {
                    return;
                }

                const {
                    conversationId,
                    messageId
                } = payload || {};

                if (
                    !isValidId(conversationId) ||
                    !isValidId(messageId)
                ) {
                    return;
                }

                const hasAccess = await verifyConversationAccess(
                    socket,
                    conversationId
                );

                if (!hasAccess) {
                    return;
                }

                const message = await Message.findOne({
                    _id: messageId,
                    conversationId,
                    sender: {
                        $ne: socket.user._id
                    }
                });

                if (!message) {
                    return;
                }

                message.deliveryStatus = "read";

                if (!message.readAt) {
                    message.readAt = new Date();
                }

                await message.save();

                io.to(
                    `conversation:${conversationId}`
                ).emit("message_status_updated", {
                    conversationId,
                    messageId,
                    userId,
                    deliveryStatus: "read",
                    readAt: message.readAt
                });

            } catch (error) {
                console.error(
                    "MESSAGE READ ERROR:",
                    error.message
                );
            }
        }
    );

    // ======================================
    // DISCONNECT AND REDIS PRESENCE CLEANUP
    // ======================================

    socket.on("disconnect", async () => {
        if (presenceHeartbeat) {
            clearInterval(presenceHeartbeat);
            presenceHeartbeat = null;
        }

        try {
            await presenceReady;

            const remainingConnections =
                await removeSocketPresence(
                    userId,
                    socket.id
                );

            if (remainingConnections === 0) {
                io.emit("user_offline", { userId });
            }

        } catch (error) {
            console.error(
                "[PRESENCE CLEANUP ERROR]",
                error.message
            );
        }

        console.log(
            "SecureX socket disconnected:",
            userId,
            "Device:",
            deviceId
        );
    });
});

// ==========================================
// 17. SERVER STARTUP
// ==========================================

const PORT = process.env.PORT || 5000;

async function startServer() {
    try {
        if (
            !process.env.JWT_SECRET ||
            process.env.JWT_SECRET.length < 32 ||
            !process.env.MONGODB_URI ||
            !process.env.REDIS_URL
        ) {
            throw new Error(
                "Missing required environment configuration."
            );
        }

        await connectRedis();

        console.log("SecureX Redis initialized.");

        const {
            pubClient,
            subClient
        } = getRedisPubSubClients();

        io.adapter(
            createAdapter(pubClient, subClient)
        );

        console.log(
            "SecureX Socket.IO Redis Adapter initialized."
        );

        await mongoose.connect(
            process.env.MONGODB_URI
        );

        console.log(
            "MongoDB connected successfully!"
        );

        server.listen(PORT, () => {
            console.log(
                `SecureX server running on port ${PORT}`
            );

            console.log(
                "SecureX authenticated Socket.IO initialized"
            );

            console.log(
                "JWT authentication and device validation enabled"
            );

            console.log(
                "Redis-backed HTTP rate limiting enabled"
            );

            console.log(
                "Redis-backed Socket.IO rate limiting enabled"
            );

            console.log(
                "Socket.IO Redis Adapter enabled"
            );

            console.log(
                "Redis-backed online presence enabled"
            );

            console.log(
                "Multi-device session routes enabled"
            );

            console.log(
                "PlayCipher threat detection enabled"
            );

            console.log(
                "PlayCipher persistent security event logging enabled"
            );

            console.log(
                "Security middleware initialized"
            );

            console.log(
                `Authentication limit: ${
                    process.env.NODE_ENV === "production"
                        ? 30
                        : 100
                } attempts per 15 minutes`
            );
        });

    } catch (error) {
        console.error(
            "SecureX startup failed:",
            error.message
        );

        process.exit(1);
    }
}

// ==========================================
// 18. GRACEFUL SHUTDOWN
// ==========================================

let shuttingDown = false;

async function shutdown(signal) {
    if (shuttingDown) return;

    shuttingDown = true;

    console.log(
        `${signal} received. Shutting down SecureX...`
    );

    try {
        await new Promise((resolve) => {
            io.close(() => resolve());
        });

        await mongoose.disconnect();
        await closeRedis();

        console.log(
            "SecureX shutdown completed."
        );

        process.exit(0);

    } catch (error) {
        console.error(
            "Shutdown error:",
            error.message
        );

        process.exit(1);
    }
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

// ==========================================
// 19. START APPLICATION
// ==========================================

startServer();