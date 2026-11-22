import {
    encryptAttachmentForConversation,
    decryptAttachmentForCurrentUser,
} from "../utils/attachmentCrypto.js";

import {
    uploadEncryptedAttachment,
    downloadEncryptedAttachment,
} from "./attachmentService.js";

function isGroupConversation(conversation) {
    if (conversation?.conversationType) {
        return conversation.conversationType === "group";
    }

    return (
        conversation?.isGroup === true ||
        conversation?.type === "group" ||
        Boolean(conversation?.groupName) ||
        (conversation?.participants?.length || 0) > 2
    );
}

/* =========================================
   ENCRYPT AND UPLOAD
========================================= */

export async function prepareAndUploadAttachment({
    file,
    conversation,
}) {
    if (!file) {
        throw new Error("Please select a file.");
    }

    const conversationId = String(
        conversation?._id || conversation?.id || ""
    );

    if (!conversationId) {
        throw new Error("Conversation ID is missing.");
    }

    if (
        !Array.isArray(conversation.participants) ||
        conversation.participants.length === 0
    ) {
        throw new Error(
            "Conversation participants are unavailable."
        );
    }

    const group = isGroupConversation(conversation);

    const encrypted = await encryptAttachmentForConversation(
        file,
        conversation.participants,
        conversationId,
        group
    );

    const result = await uploadEncryptedAttachment({
        conversationId,
        encryptedBlob: encrypted.encryptedBlob,
        encryptedMetadata: encrypted.encryptedMetadata,
        fileIv: encrypted.fileIv,
        metadataIv: encrypted.metadataIv,
        recipientKeyEnvelopes: encrypted.recipientKeyEnvelopes,
    });

    if (!result?.success || !result?.attachment?._id) {
        throw new Error(
            result?.message ||
            "Encrypted attachment upload failed."
        );
    }

    return {
        attachmentId: result.attachment._id,
        attachment: result.attachment,
    };
}

/* =========================================
   DOWNLOAD AND DECRYPT
========================================= */

export async function downloadAndDecryptAttachment(
    attachmentInput
) {
    const attachmentId =
        typeof attachmentInput === "string"
            ? attachmentInput
            : attachmentInput?.attachmentId;

    if (!attachmentId) {
        throw new Error("Attachment ID is missing.");
    }

    const encryptedAttachment =
        await downloadEncryptedAttachment(attachmentId);

    if (!encryptedAttachment) {
        throw new Error(
            "Unable to download encrypted attachment."
        );
    }

    const decrypted = await decryptAttachmentForCurrentUser(
        encryptedAttachment
    );

    if (!decrypted?.file || !decrypted?.objectURL) {
        throw new Error(
            "Attachment decryption failed."
        );
    }

    return {
        file: decrypted.file,
        metadata: decrypted.metadata,
        objectURL: decrypted.objectURL,
    };
}

/* =========================================
   OPEN ATTACHMENT
========================================= */

export async function openSecureAttachment(attachmentId) {
    const openedWindow = window.open("about:blank", "_blank");

    if (!openedWindow) {
        throw new Error(
            "Please allow pop-ups for SecureX."
        );
    }

    try {
        const result =
            await downloadAndDecryptAttachment(attachmentId);

        openedWindow.location.href = result.objectURL;

        return result;
    } catch (error) {
        openedWindow.close();
        throw error;
    }
}

/* =========================================
   SAVE ATTACHMENT
========================================= */

export async function saveSecureAttachment(attachmentId) {
    const result =
        await downloadAndDecryptAttachment(attachmentId);

    if (!result?.objectURL) {
        throw new Error(
            "Unable to prepare attachment download."
        );
    }

    const link = document.createElement("a");

    link.href = result.objectURL;

    link.download =
        result.metadata?.name || "SecureX-file";

    document.body.appendChild(link);
    link.click();
    link.remove();

    return result;
}