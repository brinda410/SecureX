import { getCryptoSession } from "./cryptoSession.js";

import {
    encryptFile,
    decryptFile,
    exportFileEncryptionKey,
} from "./fileEncryption.js";

import {
    getGroupAESKey,
    clearGroupKeyCache,
} from "./messageEncryption.js";

const RSA_ALGORITHM = "RSA-OAEP";
const RSA_HASH = "SHA-256";
const EXPECTED_RSA_MODULUS_LENGTH = 3072;
const MAX_PARTICIPANTS = 100;

/* =========================================
   HELPERS
========================================= */

function toBase64(bytes) {
    const array = new Uint8Array(bytes);
    let binary = "";

    for (const byte of array) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}

function fromBase64(value) {
    if (typeof value !== "string" || !value.trim()) {
        throw new Error("Invalid encryption data.");
    }

    const normalized = value.trim();

    if (
        normalized.length % 4 !== 0 ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(normalized)
    ) {
        throw new Error("Invalid Base64 encryption data.");
    }

    const binary = atob(normalized);

    return Uint8Array.from(binary, character =>
        character.charCodeAt(0)
    );
}

function getParticipantId(participant) {
    if (!participant) return "";

    if (typeof participant === "string") {
        return participant.trim().toLowerCase();
    }

    if (typeof participant.toHexString === "function") {
        return participant.toHexString().toLowerCase();
    }

    const id =
        participant._id ||
        participant.id ||
        participant.userId;

    if (!id) return "";

    return String(id).trim().toLowerCase();
}

function normalizeId(value) {
    return String(value || "").trim().toLowerCase();
}

function validateSession() {
    const session = getCryptoSession();

    if (!session?.privateKey || !session?.userId) {
        throw new Error(
            "Your SecureX encryption session is unavailable. Please log in again."
        );
    }

    return session;
}

/* =========================================
   RSA KEY WRAPPING
========================================= */

function normalizePublicKey(value) {
    if (!value || typeof value !== "string") {
        throw new Error(
            "A participant's encryption public key is missing."
        );
    }

    return value
        .replace(/-----BEGIN PUBLIC KEY-----/g, "")
        .replace(/-----END PUBLIC KEY-----/g, "")
        .replace(/\s/g, "");
}

async function importRecipientPublicKey(encodedKey) {
    const keyBytes = fromBase64(
        normalizePublicKey(encodedKey)
    );

    const publicKey = await window.crypto.subtle.importKey(
        "spki",
        keyBytes,
        {
            name: RSA_ALGORITHM,
            hash: RSA_HASH,
        },
        false,
        ["encrypt"]
    );

    if (
        publicKey.algorithm.name !== RSA_ALGORITHM ||
        publicKey.algorithm.modulusLength !== EXPECTED_RSA_MODULUS_LENGTH
    ) {
        throw new Error(
            "The participant's encryption public key is invalid."
        );
    }

    return publicKey;
}

async function wrapFileKey(fileKey, publicKey) {
    const recipientKey = await importRecipientPublicKey(
        publicKey
    );

    const rawKey = fromBase64(fileKey);

    if (rawKey.length !== 32) {
        throw new Error("Invalid AES-256 encryption key.");
    }

    const wrapped = await window.crypto.subtle.encrypt(
        {
            name: RSA_ALGORITHM,
        },
        recipientKey,
        rawKey
    );

    return toBase64(wrapped);
}

async function unwrapFileKey(wrappedAESKey, privateKey) {
    if (!privateKey) {
        throw new Error(
            "Your private encryption key is unavailable."
        );
    }

    if (
        privateKey.algorithm.name !== RSA_ALGORITHM ||
        privateKey.algorithm.modulusLength !== EXPECTED_RSA_MODULUS_LENGTH
    ) {
        throw new Error("Your private encryption key is invalid.");
    }

    const rawKey = await window.crypto.subtle.decrypt(
        {
            name: RSA_ALGORITHM,
        },
        privateKey,
        fromBase64(wrappedAESKey)
    );

    if (rawKey.byteLength !== 32) {
        throw new Error(
            "The decrypted attachment key is invalid."
        );
    }

    return toBase64(new Uint8Array(rawKey));
}

/* =========================================
   ATTACHMENT ENCRYPTION
========================================= */

export async function encryptAttachmentForConversation(
    file,
    participants,
    conversationId,
    isGroup = false
) {
    const session = validateSession();

    if (!Array.isArray(participants) || participants.length === 0) {
        throw new Error(
            "Conversation participants are unavailable."
        );
    }

    if (participants.length > MAX_PARTICIPANTS) {
        throw new Error(
            "The conversation exceeds the supported participant limit."
        );
    }

    if (isGroup && !conversationId) {
        throw new Error(
            "Conversation ID is required for group attachment encryption."
        );
    }

    const participantMap = new Map();

    for (const participant of participants) {
        const userId = getParticipantId(participant);

        if (!userId) {
            throw new Error(
                "A conversation participant has an invalid user ID."
            );
        }

        if (participantMap.has(userId)) {
            throw new Error(
                "Duplicate conversation participants were detected."
            );
        }

        if (
            typeof participant !== "object" ||
            !participant.publicKey
        ) {
            throw new Error(
                "An encryption public key is missing for a conversation participant."
            );
        }

        participantMap.set(userId, participant);
    }

    const currentUserId = normalizeId(session.userId);

    if (!participantMap.has(currentUserId)) {
        throw new Error(
            "Your account is not a member of this conversation."
        );
    }

    /*
     * GROUP:
     * Retrieve the current rotated group AES key.
     *
     * PRIVATE:
     * Generate a fresh AES key for this attachment.
     */

    let encryptionKey = null;

    if (isGroup) {
        encryptionKey = await getGroupAESKey(conversationId);
    }

    /*
     * Encrypt file and metadata.
     * Each encryption generates fresh random IVs.
     */

    const encrypted = await encryptFile(
        file,
        encryptionKey
    );

    if (
        !encrypted?.encryptedBlob ||
        !encrypted?.fileKey ||
        !encrypted?.fileIV ||
        !encrypted?.encryptedMetadata ||
        !encrypted?.metadataIV
    ) {
        throw new Error(
            "File encryption did not produce valid encrypted data."
        );
    }

    /*
     * For group attachments, encrypted.fileKey represents
     * the current group AES key.
     *
     * For private attachments, it represents the fresh
     * attachment-specific AES key.
     *
     * Wrap the appropriate key for each participant.
     */

    const recipientKeyEnvelopes = [];

    for (const [userId, participant] of participantMap.entries()) {
        const wrappedAESKey = await wrapFileKey(
            encrypted.fileKey,
            participant.publicKey
        );

        recipientKeyEnvelopes.push({
            userId,
            wrappedAESKey,
        });
    }

    if (
        recipientKeyEnvelopes.length !== participantMap.size
    ) {
        throw new Error(
            "The encryption key could not be shared with every participant."
        );
    }

    return {
        encryptedBlob: encrypted.encryptedBlob,
        encryptedMetadata: encrypted.encryptedMetadata,
        fileIv: encrypted.fileIV,
        metadataIv: encrypted.metadataIV,
        recipientKeyEnvelopes,
        algorithm: "AES-256-GCM",
        keyEncryptionAlgorithm: "RSA-OAEP-SHA256",
    };
}

/* =========================================
   ATTACHMENT DECRYPTION
========================================= */

export async function decryptAttachmentForCurrentUser(
    encryptedAttachment
) {
    const session = validateSession();

    if (!encryptedAttachment?.wrappedAESKey) {
        throw new Error(
            "No encryption key was provided for this attachment."
        );
    }

    if (!encryptedAttachment?.encryptedBlob) {
        throw new Error(
            "Encrypted attachment data is missing."
        );
    }

    const {
        encryptedMetadata,
        fileIv,
        metadataIv,
    } = encryptedAttachment;

    if (!encryptedMetadata || !fileIv || !metadataIv) {
        throw new Error(
            "Attachment encryption metadata is incomplete."
        );
    }

    /*
     * Recover the attachment AES key using
     * the logged-in user's private key.
     */

    const fileKey = await unwrapFileKey(
        encryptedAttachment.wrappedAESKey,
        session.privateKey
    );

    /*
     * Decrypt file and metadata locally.
     */

    const result = await decryptFile({
        encryptedBlob: encryptedAttachment.encryptedBlob,
        encryptedMetadata,
        fileIV: fileIv,
        metadataIV: metadataIv,
        fileKey,
    });

    if (!result?.file || !result?.objectURL) {
        throw new Error(
            "The attachment could not be decrypted."
        );
    }

    return {
        file: result.file,
        metadata: result.metadata,
        objectURL: result.objectURL,
    };
}