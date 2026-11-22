import { getCryptoSession } from "../utils/cryptoSession.js";

// ==========================================
// SECUREX MESSAGE API CONFIGURATION
// ==========================================

const API_BASE_URL = (
    import.meta.env.VITE_API_URL || "/api"
).replace(/\/+$/, "");

const API_URL = `${API_BASE_URL}/messages`;

// ==========================================
// AUTHENTICATION HEADERS
// ==========================================

function getAuthHeaders(isJSON = false) {
    const session = getCryptoSession();

    if (!session?.token) {
        throw new Error(
            "Your SecureX session has expired. Please log in again."
        );
    }

    const headers = {
        Authorization: `Bearer ${session.token}`,
        Accept: "application/json"
    };

    if (isJSON) {
        headers["Content-Type"] = "application/json";
    }

    return headers;
}

// ==========================================
// HANDLE SERVER RESPONSE
// ==========================================

async function handleResponse(response) {
    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
        throw new Error(
            data.message ||
            data.error ||
            `Request failed with status ${response.status}`
        );
    }

    return data;
}

// ==========================================
// EXTRACT SAVED MESSAGE
// ==========================================

function extractMessage(data) {
    if (!data) return null;

    if (data.data && typeof data.data === "object") {
        if (
            data.data.message &&
            typeof data.data.message === "object"
        ) {
            return data.data.message;
        }

        return data.data;
    }

    if (
        data.message &&
        typeof data.message === "object"
    ) {
        return data.message;
    }

    return null;
}

// ==========================================
// SEND ENCRYPTED MESSAGE
// ==========================================

export async function sendEncryptedMessage(
    conversationId,
    encryptedPayload
) {
    if (
        typeof conversationId !== "string" ||
        !conversationId.trim()
    ) {
        throw new Error("Conversation ID is required.");
    }

    if (
        !encryptedPayload ||
        typeof encryptedPayload !== "object" ||
        Array.isArray(encryptedPayload)
    ) {
        throw new Error("Encrypted message payload is invalid.");
    }

    const response = await fetch(API_URL, {
        method: "POST",
        headers: getAuthHeaders(true),
        body: JSON.stringify({
            ...encryptedPayload,
            conversationId
        })
    });

    const data = await handleResponse(response);
    const savedMessage = extractMessage(data);

    if (!savedMessage) {
        throw new Error(
            "The server did not return the saved message. Please refresh the conversation."
        );
    }

    return {
        success: data.success !== false,
        message: savedMessage,
        data
    };
}

// ==========================================
// RETRIEVE ENCRYPTED MESSAGES
// ==========================================

export async function getEncryptedMessages(conversationId) {
    if (
        typeof conversationId !== "string" ||
        !conversationId.trim()
    ) {
        throw new Error("Conversation ID is required.");
    }

    const response = await fetch(
        `${API_URL}/${encodeURIComponent(conversationId)}`,
        {
            method: "GET",
            headers: getAuthHeaders()
        }
    );

    const data = await handleResponse(response);

    if (Array.isArray(data)) {
        return data;
    }

    if (Array.isArray(data.messages)) {
        return data.messages;
    }

    if (Array.isArray(data.data)) {
        return data.data;
    }

    if (Array.isArray(data.data?.messages)) {
        return data.data.messages;
    }

    return [];
}