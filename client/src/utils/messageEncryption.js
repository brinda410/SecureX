import {
    generateAESKey,
    encryptMessage,
    decryptMessage,
    wrapAESKey,
    unwrapAESKey,
} from "./crypto.js";

import { fetchUserPublicKey } from "./publicKeyService.js";
import { getCryptoSession } from "./cryptoSession.js";

const API_BASE = "http://localhost:5000/api";

const groupKeyCache = new Map();

/* =========================================
   HELPERS
========================================= */

function getId(value) {
    if (!value) return "";

    if (typeof value.toHexString === "function") {
        return value.toHexString();
    }

    if (typeof value === "object") {
        return String(
            value._id ||
            value.id ||
            value.userId ||
            ""
        );
    }

    return String(value);
}

function normalizeId(value) {
    return getId(value).toLowerCase();
}

function validateMessage(message) {
    if (typeof message !== "string" || !message.trim()) {
        throw new Error("Message cannot be empty.");
    }
}

function validateSession() {
    const session = getCryptoSession();

    if (!session?.token || !session?.privateKey || !session?.userId) {
        throw new Error(
            "Please unlock your SecureX encryption session first."
        );
    }

    return session;
}

function normalizePlaintext(value) {
    if (typeof value === "string") return value;

    if (
        typeof value === "number" ||
        typeof value === "boolean"
    ) {
        return String(value);
    }

    if (value && typeof value === "object") {
        if (typeof value.text === "string") return value.text;
        if (typeof value.plaintext === "string") return value.plaintext;
        if (typeof value.message === "string") return value.message;
        if (typeof value.content === "string") return value.content;
    }

    throw new Error("Decrypted message has an unsupported format.");
}

async function apiRequest(endpoint, options = {}) {
    const session = validateSession();

    const response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers: {
            Authorization: `Bearer ${session.token}`,
            Accept: "application/json",
            ...(options.body
                ? { "Content-Type": "application/json" }
                : {}),
            ...options.headers,
        },
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
        const error = new Error(
            data.message || `Request failed (${response.status})`
        );

        error.status = response.status;
        throw error;
    }

    return data;
}

/* =========================================
   GROUP KEY STATE
========================================= */

export async function getGroupKeyState(conversationId) {
    if (!conversationId) {
        throw new Error("Conversation ID is required.");
    }

    return apiRequest(
        `/group-keys/${encodeURIComponent(conversationId)}`
    );
}

async function getMyGroupKeyEnvelope(conversationId) {
    return apiRequest(
        `/group-keys/${encodeURIComponent(conversationId)}/my-envelope`
    );
}

/* =========================================
   GROUP KEY RETRIEVAL
========================================= */

export async function getGroupAESKey(conversationId) {
    const session = validateSession();

    const state = await getGroupKeyState(conversationId);

    if (state.rotationRequired || !state.envelopeAvailable) {
        throw new Error(
            "GROUP_KEY_ROTATION_REQUIRED: A group administrator must rotate the group key."
        );
    }

    const cacheKey = `${conversationId}:${state.epoch}`;

    if (groupKeyCache.has(cacheKey)) {
        return groupKeyCache.get(cacheKey);
    }

    const envelope = await getMyGroupKeyEnvelope(conversationId);

    if (
        !envelope?.encryptedKey ||
        envelope.epoch !== state.epoch
    ) {
        throw new Error("Group key envelope is missing or outdated.");
    }

    const aesKey = await unwrapAESKey(
        envelope.encryptedKey,
        session.privateKey
    );

    if (
        aesKey.algorithm?.name !== "AES-GCM" ||
        aesKey.algorithm?.length !== 256
    ) {
        throw new Error("Invalid group AES encryption key.");
    }

    groupKeyCache.set(cacheKey, aesKey);

    return aesKey;
}

/* =========================================
   GROUP KEY ROTATION
========================================= */

export async function rotateGroupKey(conversationId) {
    validateSession();

    if (!conversationId) {
        throw new Error("Conversation ID is required.");
    }

    const state = await getGroupKeyState(conversationId);

    if (!Array.isArray(state.members) || state.members.length < 2) {
        throw new Error("Invalid group membership.");
    }

    if (!state.rotationRequired) {
        return {
            success: true,
            rotated: false,
            epoch: state.epoch,
            message: "Group key is already up to date.",
        };
    }

    const members = [
        ...new Set(state.members.map(getId).filter(Boolean)),
    ];

    if (members.length !== state.members.length) {
        throw new Error("Duplicate or invalid group members.");
    }

    /*
     * Generate a completely new group AES key.
     */
    const groupAESKey = await generateAESKey();

    /*
     * Encrypt the new group key separately for every member.
     */
    const envelopes = await Promise.all(
        members.map(async (userId) => {
            const recipient = await fetchUserPublicKey(userId);

            if (
                normalizeId(recipient.userId) !== normalizeId(userId)
            ) {
                throw new Error(
                    `Public key identity mismatch for member ${userId}.`
                );
            }

            return {
                userId,
                encryptedKey: await wrapAESKey(
                    groupAESKey,
                    recipient.publicKey
                ),
            };
        })
    );

    const nextEpoch = Number(state.epoch || 0) + 1;

    const result = await apiRequest(
        `/group-keys/${encodeURIComponent(conversationId)}/rotate`,
        {
            method: "POST",
            body: JSON.stringify({
                epoch: nextEpoch,
                envelopes,
            }),
        }
    );

    if (!result.success || result.epoch !== nextEpoch) {
        throw new Error("Group key rotation could not be confirmed.");
    }

    /*
     * Remove previous cached keys for this group.
     */
    clearGroupKeyCache(conversationId);

    /*
     * Cache the newly generated key for this session.
     */
    groupKeyCache.set(
        `${conversationId}:${nextEpoch}`,
        groupAESKey
    );

    return {
        success: true,
        rotated: true,
        epoch: nextEpoch,
        memberCount: members.length,
    };
}

/* =========================================
   PRIVATE MESSAGE ENCRYPTION
========================================= */

export async function encryptMessageForRecipient(
    message,
    recipientId,
    clientMessageId
) {
    validateMessage(message);

    const session = validateSession();

    const senderId = getId(session.userId);
    const targetId = getId(recipientId);

    if (!targetId) {
        throw new Error("Recipient ID is required.");
    }

    if (normalizeId(senderId) === normalizeId(targetId)) {
        throw new Error("You cannot message yourself.");
    }

    if (!clientMessageId) {
        throw new Error("Message ID is required.");
    }

    const [recipient, sender] = await Promise.all([
        fetchUserPublicKey(targetId),
        fetchUserPublicKey(senderId),
    ]);

    if (!recipient?.publicKey || !sender?.publicKey) {
        throw new Error("Unable to retrieve encryption keys.");
    }

    const aesKey = await generateAESKey();

    const encrypted = await encryptMessage(message, aesKey);

    const [wrappedAESKey, senderWrappedAESKey] =
        await Promise.all([
            wrapAESKey(aesKey, recipient.publicKey),
            wrapAESKey(aesKey, sender.publicKey),
        ]);

    return {
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        wrappedAESKey,
        senderWrappedAESKey,
        clientMessageId,
        algorithm: "AES-256-GCM",
        keyEncryptionAlgorithm: "RSA-OAEP-SHA256",
        messageType: "text",
    };
}

/* =========================================
   GROUP MESSAGE ENCRYPTION
========================================= */

export async function encryptMessageForGroup(
    message,
    participantIds,
    clientMessageId,
    conversationId
) {
    validateMessage(message);
    validateSession();

    if (!conversationId) {
        throw new Error(
            "Conversation ID is required for group encryption."
        );
    }

    if (!clientMessageId) {
        throw new Error("Message ID is required.");
    }

    if (!Array.isArray(participantIds)) {
        throw new Error("Invalid group participants.");
    }

    const senderId = getId(getCryptoSession().userId);

    const members = [
        ...new Set(
            participantIds.map(getId).filter(Boolean)
        ),
    ];

    if (
        !members.some(
            (id) => normalizeId(id) === normalizeId(senderId)
        )
    ) {
        members.push(senderId);
    }

    if (members.length < 2) {
        throw new Error("A group requires at least two members.");
    }

    /*
     * Retrieve the actual rotated group key.
     */
    const groupAESKey = await getGroupAESKey(conversationId);

    /*
     * Encrypt message with the group AES key.
     * A fresh IV is generated for every message.
     */
    const encrypted = await encryptMessage(
        message,
        groupAESKey
    );

    /*
     * Generate message envelopes for all members.
     */
    const recipientKeyEnvelopes = await Promise.all(
        members.map(async (userId) => {
            const recipient = await fetchUserPublicKey(userId);

            if (
                normalizeId(recipient.userId) !== normalizeId(userId)
            ) {
                throw new Error(
                    `Public key identity mismatch for ${userId}.`
                );
            }

            return {
                userId,
                wrappedAESKey: await wrapAESKey(
                    groupAESKey,
                    recipient.publicKey
                ),
            };
        })
    );

    const envelopeIds = recipientKeyEnvelopes.map(
        (entry) => normalizeId(entry.userId)
    );

    if (
        new Set(envelopeIds).size !== members.length ||
        members.some(
            (member) => !envelopeIds.includes(normalizeId(member))
        )
    ) {
        throw new Error(
            "Missing or duplicated group key envelopes."
        );
    }

    return {
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        recipientKeyEnvelopes,
        clientMessageId,
        algorithm: "AES-256-GCM",
        keyEncryptionAlgorithm: "RSA-OAEP-SHA256",
        messageType: "text",
    };
}

/* =========================================
   STORED MESSAGE DECRYPTION
========================================= */

export async function decryptStoredMessage(message) {
    const session = validateSession();

    if (!message || typeof message !== "object") {
        throw new Error("Invalid encrypted message.");
    }

    if (!message.ciphertext || !message.iv) {
        throw new Error("Encrypted message data is incomplete.");
    }

    const currentUserId = getId(session.userId);

    let wrappedAESKey = null;

    /*
     * GROUP MESSAGE
     */
    if (
        Array.isArray(message.recipientKeyEnvelopes) &&
        message.recipientKeyEnvelopes.length > 0
    ) {
        const myEnvelope = message.recipientKeyEnvelopes.find(
            (envelope) =>
                normalizeId(envelope.userId) ===
                normalizeId(currentUserId)
        );

        if (!myEnvelope?.wrappedAESKey) {
            throw new Error(
                "Your group encryption envelope was not found."
            );
        }

        wrappedAESKey = myEnvelope.wrappedAESKey;
    } else {
        /*
         * PRIVATE MESSAGE
         */
        const sender = (
            message.sender ||
            message.senderId ||
            message.user ||
            message.userId ||
            null
        );

        const senderId = getId(sender);

        const isSender =
            normalizeId(senderId) === normalizeId(currentUserId);

        wrappedAESKey = isSender
            ? message.senderWrappedAESKey
            : message.wrappedAESKey;

        if (!wrappedAESKey) {
            throw new Error(
                "Your encrypted message key was not found."
            );
        }
    }

    const aesKey = await unwrapAESKey(
        wrappedAESKey,
        session.privateKey
    );

    const plaintext = await decryptMessage(
        message.ciphertext,
        message.iv,
        aesKey
    );

    return normalizePlaintext(plaintext);
}

/* =========================================
   CACHE MANAGEMENT
========================================= */

export function clearGroupKeyCache(conversationId) {
    if (!conversationId) {
        groupKeyCache.clear();
        return;
    }

    for (const key of groupKeyCache.keys()) {
        if (key.startsWith(`${conversationId}:`)) {
            groupKeyCache.delete(key);
        }
    }
}

/* =========================================
   SESSION VALIDATION
========================================= */

export function validateEncryptionSession() {
    try {
        validateSession();
        return true;
    } catch {
        return false;
    }
}