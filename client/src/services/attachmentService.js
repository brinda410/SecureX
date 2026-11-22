import { getCryptoSession } from "../utils/cryptoSession.js";

// ==========================================
// SECUREX ATTACHMENT API
// ==========================================

const API_BASE_URL = (
    import.meta.env.VITE_API_URL || "/api"
).replace(/\/+$/, "");

const API_URL = `${API_BASE_URL}/messages`;

const MAX_ENCRYPTED_FILE_SIZE = 26 * 1024 * 1024;

// ==========================================
// AUTHENTICATION
// ==========================================

function getAuthHeaders() {
    const session = getCryptoSession();

    if (!session?.token) {
        throw new Error(
            "Your SecureX session has expired. Please log in again."
        );
    }

    return {
        Authorization: `Bearer ${session.token}`,
        Accept: "application/json"
    };
}

// ==========================================
// SERVER RESPONSE
// ==========================================

async function handleResponse(response) {
    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
        throw new Error(
            data.message ||
            data.error ||
            `Attachment request failed (${response.status}).`
        );
    }

    return data;
}

// ==========================================
// UPLOAD ENCRYPTED ATTACHMENT
// ==========================================

export async function uploadEncryptedAttachment({
    conversationId,
    encryptedBlob,
    encryptedFile,
    encryptedMetadata,
    fileIv,
    metadataIv,
    recipientKeyEnvelopes
}) {
    const fileToUpload = encryptedBlob || encryptedFile;

    if (
        typeof conversationId !== "string" ||
        !conversationId.trim()
    ) {
        throw new Error("Conversation ID is missing.");
    }

    if (!(fileToUpload instanceof Blob)) {
        throw new Error("Encrypted attachment must be a Blob.");
    }

    if (fileToUpload.size === 0) {
        throw new Error("Encrypted attachment is empty.");
    }

    if (fileToUpload.size > MAX_ENCRYPTED_FILE_SIZE) {
        throw new Error("Encrypted attachment exceeds the 26 MB limit.");
    }

    if (
        typeof encryptedMetadata !== "string" ||
        !encryptedMetadata ||
        typeof fileIv !== "string" ||
        typeof metadataIv !== "string"
    ) {
        throw new Error("Encrypted attachment metadata is incomplete.");
    }

    if (
        !Array.isArray(recipientKeyEnvelopes) ||
        recipientKeyEnvelopes.length === 0 ||
        recipientKeyEnvelopes.length > 100
    ) {
        throw new Error("Invalid attachment encryption envelopes.");
    }

    const envelopeUserIds = recipientKeyEnvelopes.map(
        envelope => String(envelope?.userId || "")
    );

    if (
        envelopeUserIds.some(id => !id) ||
        new Set(envelopeUserIds).size !== envelopeUserIds.length ||
        recipientKeyEnvelopes.some(
            envelope =>
                typeof envelope?.wrappedAESKey !== "string" ||
                !envelope.wrappedAESKey
        )
    ) {
        throw new Error("Invalid or duplicate recipient key envelopes.");
    }

    const formData = new FormData();

    formData.append("conversationId", conversationId);

    formData.append(
        "file",
        fileToUpload,
        "securex-encrypted-file.enc"
    );

    formData.append("encryptedMetadata", encryptedMetadata);
    formData.append("fileIv", fileIv);
    formData.append("metadataIv", metadataIv);

    formData.append(
        "recipientKeyEnvelopes",
        JSON.stringify(recipientKeyEnvelopes)
    );

    const response = await fetch(
        `${API_URL}/attachments`,
        {
            method: "POST",
            headers: getAuthHeaders(),
            body: formData
        }
    );

    const data = await handleResponse(response);

    const payload =
        data.data && typeof data.data === "object"
            ? data.data
            : data;

    const attachment =
        payload.attachment ||
        data.attachment ||
        (payload._id ? payload : null);

    if (!attachment?._id) {
        throw new Error(
            "The server did not return an attachment ID."
        );
    }

    return {
        ...data,
        success: data.success !== false,
        attachment
    };
}

// ==========================================
// DOWNLOAD ENCRYPTED ATTACHMENT
// ==========================================

export async function downloadEncryptedAttachment(attachmentId) {
    if (
        typeof attachmentId !== "string" ||
        !attachmentId.trim()
    ) {
        throw new Error("Attachment ID is required.");
    }

    const response = await fetch(
        `${API_URL}/attachments/${encodeURIComponent(attachmentId)}`,
        {
            method: "GET",
            headers: getAuthHeaders()
        }
    );

    const data = await handleResponse(response);

    const payload =
        data.data && typeof data.data === "object"
            ? data.data
            : data;

    if (
        typeof payload.encryptedFile !== "string" ||
        typeof payload.encryptedMetadata !== "string" ||
        typeof payload.fileIv !== "string" ||
        typeof payload.metadataIv !== "string" ||
        typeof payload.wrappedAESKey !== "string"
    ) {
        throw new Error(
            "Encrypted attachment response is incomplete."
        );
    }

    let binaryString;

    try {
        binaryString = atob(payload.encryptedFile);
    } catch {
        throw new Error(
            "The encrypted attachment data is invalid."
        );
    }

    if (
        binaryString.length === 0 ||
        binaryString.length > MAX_ENCRYPTED_FILE_SIZE
    ) {
        throw new Error(
            "Downloaded encrypted attachment has an invalid size."
        );
    }

    const bytes = new Uint8Array(binaryString.length);

    for (let index = 0; index < binaryString.length; index++) {
        bytes[index] = binaryString.charCodeAt(index);
    }

    const encryptedBlob = new Blob(
        [bytes],
        { type: "application/octet-stream" }
    );

    return {
        encryptedBlob,
        encryptedMetadata: payload.encryptedMetadata,
        fileIv: payload.fileIv,
        metadataIv: payload.metadataIv,
        wrappedAESKey: payload.wrappedAESKey,
        algorithm: payload.algorithm || "AES-256-GCM"
    };
}
