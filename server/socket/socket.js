import jwt from "jsonwebtoken";
import mongoose from "mongoose";

import Conversation from "./models/Conversation.js";
import Message from "./models/Message.js";

// ======================================================
// HELPERS
// ======================================================

const isValidId = (id) => {
    return (
        typeof id === "string" &&
        mongoose.Types.ObjectId.isValid(id)
    );
};

const isValidCallback = (callback) => {
    return typeof callback === "function";
};

const isSocketConversationMember = async (
    conversationId,
    userId
) => {
    if (
        !isValidId(conversationId) ||
        !isValidId(userId)
    ) {
        return false;
    }

    const conversation = await Conversation.findOne({
        _id: conversationId,
        participants: userId
    }).select("_id");

    return Boolean(conversation);
};

const isJoinedConversation = (socket, conversationId) => {
    const room = `conversation:${conversationId}`;

    return socket.rooms.has(room);
};

// ======================================================
// REGISTER SOCKET HANDLERS
// ======================================================

export const registerSocketHandlers = (io) => {

    // ==================================================
    // SOCKET AUTHENTICATION
    // ==================================================

    io.use((socket, next) => {
        try {
            const token = socket.handshake.auth?.token;

            if (!token) {
                return next(
                    new Error("Authentication token is required.")
                );
            }

            if (!process.env.JWT_SECRET) {
                return next(
                    new Error("Server authentication is not configured.")
                );
            }

            const decoded = jwt.verify(
                token,
                process.env.JWT_SECRET
            );

            const userId =
                decoded.id ||
                decoded.userId ||
                decoded._id;

            if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
                return next(
                    new Error("Invalid authentication token.")
                );
            }

            socket.userId = String(userId);

            next();

        } catch (error) {
            console.error(
                "SOCKET AUTHENTICATION ERROR:",
                error.message
            );

            next(
                new Error("Socket authentication failed.")
            );
        }
    });

    // ==================================================
    // CONNECTION
    // ==================================================

    io.on("connection", async (socket) => {

        console.log(
            `SecureX user connected: ${socket.userId}`
        );

        // Automatically join the authenticated user's room.
        // Required for live sidebar updates and unread counts.
        socket.join(`user:${socket.userId}`);

        // ==================================================
        // JOIN CONVERSATION
        // ==================================================

        socket.on(
            "join_conversation",
            async (conversationId, callback) => {
                try {
                    if (!isValidId(conversationId)) {
                        if (isValidCallback(callback)) {
                            callback({
                                success: false,
                                message: "Invalid conversation ID."
                            });
                        }

                        return;
                    }

                    const isMember =
                        await isSocketConversationMember(
                            conversationId,
                            socket.userId
                        );

                    if (!isMember) {
                        if (isValidCallback(callback)) {
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

                    if (isValidCallback(callback)) {
                        callback({
                            success: true,
                            message: "Joined conversation successfully."
                        });
                    }

                } catch (error) {
                    console.error(
                        "JOIN CONVERSATION ERROR:",
                        error
                    );

                    if (isValidCallback(callback)) {
                        callback({
                            success: false,
                            message: "Unable to join conversation."
                        });
                    }
                }
            }
        );

        // ==================================================
        // LEAVE CONVERSATION
        // ==================================================

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
                        error
                    );
                }
            }
        );

        // ==================================================
        // TYPING INDICATOR
        // ==================================================

        socket.on(
            "typing",
            async (conversationId) => {
                try {
                    if (!isValidId(conversationId)) {
                        return;
                    }

                    const room =
                        `conversation:${conversationId}`;

                    if (!socket.rooms.has(room)) {
                        return;
                    }

                    const isMember =
                        await isSocketConversationMember(
                            conversationId,
                            socket.userId
                        );

                    if (!isMember) {
                        await socket.leave(room);
                        return;
                    }

                    socket.to(room).emit(
                        "user_typing",
                        {
                            conversationId,
                            userId: socket.userId
                        }
                    );

                } catch (error) {
                    console.error(
                        "TYPING ERROR:",
                        error
                    );
                }
            }
        );

        // ==================================================
        // STOP TYPING INDICATOR
        // ==================================================

        socket.on(
            "stop_typing",
            async (conversationId) => {
                try {
                    if (!isValidId(conversationId)) {
                        return;
                    }

                    const room =
                        `conversation:${conversationId}`;

                    if (!socket.rooms.has(room)) {
                        return;
                    }

                    const isMember =
                        await isSocketConversationMember(
                            conversationId,
                            socket.userId
                        );

                    if (!isMember) {
                        await socket.leave(room);
                        return;
                    }

                    socket.to(room).emit(
                        "user_stop_typing",
                        {
                            conversationId,
                            userId: socket.userId
                        }
                    );

                } catch (error) {
                    console.error(
                        "STOP TYPING ERROR:",
                        error
                    );
                }
            }
        );

        // ==================================================
        // MESSAGE DELIVERED
        // ==================================================

        socket.on(
            "message_delivered",
            async (payload) => {
                try {
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

                    const room =
                        `conversation:${conversationId}`;

                    if (!isJoinedConversation(socket, conversationId)) {
                        return;
                    }

                    const isMember =
                        await isSocketConversationMember(
                            conversationId,
                            socket.userId
                        );

                    if (!isMember) {
                        await socket.leave(room);
                        return;
                    }

                    const message = await Message.findOne({
                        _id: messageId,
                        conversationId,
                        sender: {
                            $ne: socket.userId
                        }
                    });

                    if (!message) {
                        return;
                    }

                    // Do not downgrade an already-read message.
                    if (message.deliveryStatus !== "read") {
                        message.deliveryStatus = "delivered";
                        message.deliveredAt = new Date();

                        await message.save();
                    }

                    const status = {
                        conversationId,
                        messageId,
                        userId: socket.userId,
                        deliveryStatus: message.deliveryStatus,
                        deliveredAt: message.deliveredAt,
                        readAt: message.readAt
                    };

                    io.to(room).emit(
                        "message_status_updated",
                        status
                    );

                } catch (error) {
                    console.error(
                        "MESSAGE DELIVERED ERROR:",
                        error
                    );
                }
            }
        );

        // ==================================================
        // MESSAGE READ
        // ==================================================

        socket.on(
            "message_read",
            async (payload) => {
                try {
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

                    const room =
                        `conversation:${conversationId}`;

                    if (!isJoinedConversation(socket, conversationId)) {
                        return;
                    }

                    const isMember =
                        await isSocketConversationMember(
                            conversationId,
                            socket.userId
                        );

                    if (!isMember) {
                        await socket.leave(room);
                        return;
                    }

                    const message = await Message.findOne({
                        _id: messageId,
                        conversationId,
                        sender: {
                            $ne: socket.userId
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

                    const status = {
                        conversationId,
                        messageId,
                        userId: socket.userId,
                        deliveryStatus: "read",
                        readAt: message.readAt
                    };

                    io.to(room).emit(
                        "message_status_updated",
                        status
                    );

                } catch (error) {
                    console.error(
                        "MESSAGE READ ERROR:",
                        error
                    );
                }
            }
        );

        // ==================================================
        // DISCONNECTION
        // ==================================================

        socket.on("disconnect", (reason) => {
            console.log(
                `SecureX user disconnected: ${socket.userId}`,
                reason
            );
        });
    });
};

export default registerSocketHandlers;