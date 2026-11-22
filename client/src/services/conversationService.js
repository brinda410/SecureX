import { getCryptoSession } from "../utils/cryptoSession.js";

const API_URL = "http://localhost:5000/api/conversations";
const MESSAGE_API_URL = "http://localhost:5000/api/messages";

const getHeaders = () => {
    const session = getCryptoSession();

    if (!session?.token) {
        throw new Error(
            "Your SecureX session has expired. Please log in again."
        );
    }

    return {
        "Content-Type": "application/json",
        Authorization: `Bearer ${session.token}`
    };
};

const handleResponse = async (response) => {
    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
        throw new Error(
            data.message ||
            data.error ||
            "Conversation request failed."
        );
    }

    return data;
};

// GET ALL CONVERSATIONS
export const getMyConversations = async () => {
    try {
        const response = await fetch(API_URL, {
            method: "GET",
            headers: getHeaders(),
            cache: "no-store"
        });

        const data = await handleResponse(response);

        console.log("SECUREX API STATUS:", response.status);
        console.log("SECUREX API DATA:", data);

        return Array.isArray(data.conversations)
            ? data.conversations
            : [];

    } catch (error) {
        console.error("SECUREX CONVERSATION ERROR:", error);
        throw error;
    }
};

// CREATE PRIVATE CONVERSATION
export const createConversation = async (recipientEmail) => {
    const email = String(recipientEmail || "")
        .trim()
        .toLowerCase();

    if (!/^[a-zA-Z0-9._%+-]+@gmail\.com$/i.test(email)) {
        throw new Error("Enter a valid Gmail address.");
    }

    const response = await fetch(API_URL, {
        method: "POST",
        headers: getHeaders(),
        body: JSON.stringify({
            recipientEmail: email
        })
    });

    const data = await handleResponse(response);
    return data.conversation;
};

// CREATE GROUP
export const createGroup = async (groupName, memberEmails) => {
    const name = String(groupName || "").trim();

    if (!name) {
        throw new Error("Enter a group name.");
    }

    if (!Array.isArray(memberEmails) || memberEmails.length < 1) {
        throw new Error("Add at least one member to the group.");
    }

    const emails = [
        ...new Set(
            memberEmails
                .map(email => String(email).trim().toLowerCase())
                .filter(Boolean)
        )
    ];

    for (const email of emails) {
        if (!/^[a-zA-Z0-9._%+-]+@gmail\.com$/i.test(email)) {
            throw new Error(`Invalid Gmail address: ${email}`);
        }
    }

    const response = await fetch(`${API_URL}/group`, {
        method: "POST",
        headers: getHeaders(),
        body: JSON.stringify({
            groupName: name,
            memberEmails: emails
        })
    });

    const data = await handleResponse(response);
    return data.conversation;
};

// ADD GROUP MEMBER
export const addGroupMember = async (conversationId, email) => {
    if (!conversationId) {
        throw new Error("Conversation ID is required.");
    }

    const normalizedEmail = String(email || "")
        .trim()
        .toLowerCase();

    if (!/^[a-zA-Z0-9._%+-]+@gmail\.com$/i.test(normalizedEmail)) {
        throw new Error("Enter a valid Gmail address.");
    }

    const response = await fetch(
        `${API_URL}/${encodeURIComponent(conversationId)}/members`,
        {
            method: "POST",
            headers: getHeaders(),
            body: JSON.stringify({
                email: normalizedEmail
            })
        }
    );

    return handleResponse(response);
};

// REMOVE GROUP MEMBER
export const removeGroupMember = async (conversationId, userId) => {
    if (!conversationId || !userId) {
        throw new Error("Conversation ID and member ID are required.");
    }

    const response = await fetch(
        `${API_URL}/${encodeURIComponent(conversationId)}/members/${encodeURIComponent(userId)}`,
        {
            method: "DELETE",
            headers: getHeaders()
        }
    );

    return handleResponse(response);
};

// LEAVE GROUP
export const leaveGroup = async (conversationId) => {
    if (!conversationId) {
        throw new Error("Conversation ID is required.");
    }

    const response = await fetch(
        `${API_URL}/${encodeURIComponent(conversationId)}/leave`,
        {
            method: "DELETE",
            headers: getHeaders()
        }
    );

    return handleResponse(response);
};

// PROMOTE GROUP ADMIN
export const transferGroupAdmin = async (
    conversationId,
    newAdminId
) => {
    if (!conversationId || !newAdminId) {
        throw new Error(
            "Conversation ID and new admin ID are required."
        );
    }

    const response = await fetch(
        `${API_URL}/${encodeURIComponent(conversationId)}/admin`,
        {
            method: "PATCH",
            headers: getHeaders(),
            body: JSON.stringify({ newAdminId })
        }
    );

    return handleResponse(response);
};

// DISMISS ANOTHER ADMIN
export const dismissGroupAdmin = async (
    conversationId,
    userId
) => {
    if (!conversationId || !userId) {
        throw new Error(
            "Conversation ID and admin ID are required."
        );
    }

    const response = await fetch(
        `${API_URL}/${encodeURIComponent(conversationId)}/admins/${encodeURIComponent(userId)}`,
        {
            method: "DELETE",
            headers: getHeaders()
        }
    );

    return handleResponse(response);
};

// RESIGN AS ADMIN WITHOUT LEAVING GROUP
export const resignGroupAdmin = async (conversationId) => {
    if (!conversationId) {
        throw new Error("Conversation ID is required.");
    }

    const response = await fetch(
        `${API_URL}/${encodeURIComponent(conversationId)}/admin/resign`,
        {
            method: "DELETE",
            headers: getHeaders()
        }
    );

    return handleResponse(response);
};

// DELETE GROUP FOR EVERYONE
export const deleteGroup = async (conversationId) => {
    if (!conversationId) {
        throw new Error("Conversation ID is required.");
    }

    const response = await fetch(
        `${API_URL}/${encodeURIComponent(conversationId)}`,
        {
            method: "DELETE",
            headers: getHeaders()
        }
    );

    return handleResponse(response);
};

// MARK CONVERSATION AS READ
export const markConversationRead = async (conversationId) => {
    if (!conversationId) {
        throw new Error("Conversation ID is required.");
    }

    const response = await fetch(
        `${MESSAGE_API_URL}/${encodeURIComponent(conversationId)}/read`,
        {
            method: "PATCH",
            headers: getHeaders()
        }
    );

    return handleResponse(response);
};