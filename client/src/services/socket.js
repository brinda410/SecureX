import { io } from "socket.io-client";

const SOCKET_URL = import.meta.env.VITE_SOCKET_URL || window.location.origin;

let socket = null;

// CONNECT AUTHENTICATED USER
export const connectSocket = (token) => {
    if (!token) {
        throw new Error("Authentication token is required.");
    }

    if (socket?.connected) {
        return socket;
    }

    if (socket) {
        socket.auth = { token };
        socket.connect();
        return socket;
    }

    socket = io(SOCKET_URL, {
        auth: { token },
        transports: ["websocket", "polling"],
        reconnection: true,
        reconnectionAttempts: 10,
        reconnectionDelay: 1000,
        timeout: 10000
    });

    socket.on("connect", () => {
        console.log("SecureX connected:", socket.id);
    });

    socket.on("connect_error", (error) => {
        console.error("SecureX connection error:", error.message);
    });

    socket.on("disconnect", (reason) => {
        console.log("SecureX disconnected:", reason);
    });

    return socket;
};

// GET SOCKET INSTANCE
export const getSocket = () => socket;

// JOIN CONVERSATION
export const joinConversation = (conversationId) => {
    return new Promise((resolve, reject) => {
        if (!socket?.connected) {
            return reject(new Error("Socket is not connected."));
        }

        socket.emit(
            "join_conversation",
            conversationId,
            (response) => {
                if (response?.success) {
                    resolve(response);
                } else {
                    reject(
                        new Error(
                            response?.message ||
                            "Unable to join conversation."
                        )
                    );
                }
            }
        );
    });
};

// LEAVE CONVERSATION
export const leaveConversation = (conversationId) => {
    if (socket?.connected) {
        socket.emit("leave_conversation", conversationId);
    }
};

// TYPING INDICATOR
export const sendTyping = (conversationId) => {
    if (socket?.connected) {
        socket.emit("typing", conversationId);
    }
};

// STOP TYPING INDICATOR
export const stopTyping = (conversationId) => {
    if (socket?.connected) {
        socket.emit("stop_typing", conversationId);
    }
};

// MESSAGE DELIVERED
export const sendMessageDelivered = (conversationId, messageId) => {
    if (socket?.connected) {
        socket.emit("message_delivered", {
            conversationId,
            messageId
        });
    }
};

// MESSAGE READ
export const sendMessageRead = (conversationId, messageId) => {
    if (socket?.connected) {
        socket.emit("message_read", {
            conversationId,
            messageId
        });
    }
};

// LISTEN FOR SOCKET EVENTS
export const subscribeToEvent = (event, callback) => {
    if (!socket) {
        return () => {};
    }

    socket.on(event, callback);

    return () => {
        socket?.off(event, callback);
    };
};

// DISCONNECT
export const disconnectSocket = () => {
    if (socket) {
        socket.removeAllListeners();
        socket.disconnect();
        socket = null;
    }
};