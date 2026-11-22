import {
  encryptMessageForRecipient,
  encryptMessageForGroup,
} from "../utils/messageEncryption.js";

import { sendEncryptedMessage } from "./messageService.js";

import {
  prepareAndUploadAttachment,
  downloadAndDecryptAttachment,
} from "./attachmentWorkflow.js";

const ATTACHMENT_PREFIX = "SECUREX_ATTACHMENT::";

function getUserId(user) {
  if (!user) return "";

  if (typeof user === "string") return user;

  return String(user._id || user.id || user.userId || "");
}

function normalizeId(value) {
  return getUserId(value).trim().toLowerCase();
}

function generateClientMessageId() {
  return globalThis.crypto?.randomUUID
    ? globalThis.crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function getParticipantIds(conversation) {
  return [
    ...new Set(
      (conversation?.participants || [])
        .map(getUserId)
        .filter(Boolean)
    ),
  ];
}

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

function getMessageType(mimeType = "") {
  const type = String(mimeType).toLowerCase();

  if (type.startsWith("image/")) return "image";
  if (type.startsWith("audio/")) return "audio";
  if (type.startsWith("video/")) return "video";

  return "file";
}

async function encryptForConversation({
  plaintext,
  conversation,
  currentUserId,
  clientMessageId,
}) {
  const participants = conversation?.participants || [];
  const participantIds = getParticipantIds(conversation);
  const senderId = normalizeId(currentUserId);

  if (
    !senderId ||
    !participantIds.some((id) => normalizeId(id) === senderId)
  ) {
    throw new Error(
      "Your account is not a member of this conversation."
    );
  }

  if (isGroupConversation(conversation)) {
    // Pass conversation ID to use the group's rotated AES key.
    return encryptMessageForGroup(
      plaintext,
      participantIds,
      clientMessageId,
      getUserId(conversation._id || conversation.id)
    );
  }

  const recipient = participants.find(
    (participant) => normalizeId(participant) !== senderId
  );

  if (!recipient) {
    throw new Error(
      "A valid recipient could not be identified."
    );
  }

  return encryptMessageForRecipient(
    plaintext,
    getUserId(recipient),
    clientMessageId
  );
}

/**
 * Encrypts the selected file on the user's device, uploads the encrypted
 * binary, and sends encrypted attachment metadata as a chat message.
 *
 * Captions and reply references are included inside encrypted plaintext.
 */
export async function sendAttachmentMessage({
  file,
  conversation,
  currentUserId,
  caption = "",
  replyTo = null,
}) {
  if (!file) {
    throw new Error("Please select a file.");
  }

  const conversationId = getUserId(
    conversation?._id || conversation?.id
  );

  if (!conversationId) {
    throw new Error("No active conversation selected.");
  }

  if (!currentUserId) {
    throw new Error("Current user could not be identified.");
  }

  if (
    !Array.isArray(conversation.participants) ||
    !conversation.participants.length
  ) {
    throw new Error("Conversation members are unavailable.");
  }

  // The workflow must encrypt file bytes before uploading them.
  const uploaded = await prepareAndUploadAttachment({
    file,
    conversation,
  });

  const attachmentId =
    uploaded?.attachmentId ||
    uploaded?.attachment?._id ||
    uploaded?._id;

  if (!attachmentId) {
    throw new Error(
      "Attachment uploaded, but its ID was not returned."
    );
  }

  const attachmentMessage = {
    attachmentId: String(attachmentId),
    name: file.name,
    type: file.type || "application/octet-stream",
    size: file.size,
    uploadedAt: new Date().toISOString(),

    caption: String(caption || "").trim(),

    replyTo: replyTo
      ? {
          messageId: String(replyTo.messageId || ""),
          senderName: String(replyTo.senderName || ""),
          preview: String(replyTo.preview || "").slice(0, 180),
        }
      : null,
  };

  const plaintext =
    ATTACHMENT_PREFIX + JSON.stringify(attachmentMessage);

  const clientMessageId = generateClientMessageId();

  const encryptedPayload = await encryptForConversation({
    plaintext,
    conversation,
    currentUserId,
    clientMessageId,
  });

  if (!encryptedPayload) {
    throw new Error("Attachment message encryption failed.");
  }

  const result = await sendEncryptedMessage(
    conversationId,
    {
      ...encryptedPayload,
      messageType: getMessageType(file.type),
    }
  );

  if (!result || result.success === false) {
    throw new Error(
      result?.message ||
      "Unable to send attachment message."
    );
  }

  return {
    success: true,
    attachmentId,
    message: result.message || result.data || result,
  };
}

/**
 * Identifies and parses attachment messages after decryption.
 */
export function parseAttachmentMessage(plaintext) {
  if (typeof plaintext !== "string") return null;

  if (!plaintext.startsWith(ATTACHMENT_PREFIX)) {
    return null;
  }

  try {
    const attachment = JSON.parse(
      plaintext.slice(ATTACHMENT_PREFIX.length)
    );

    if (!attachment?.attachmentId) return null;

    return {
      attachmentId: String(attachment.attachmentId),
      name: attachment.name || "SecureX attachment",
      type: attachment.type || "application/octet-stream",
      size: Number(attachment.size) || 0,
      uploadedAt: attachment.uploadedAt || null,
      caption: String(attachment.caption || ""),
      replyTo: attachment.replyTo || null,
    };
  } catch {
    return null;
  }
}

/**
 * Opens a decrypted attachment in a new browser tab.
 */
export async function openAttachmentMessage(attachment) {
  if (!attachment?.attachmentId) {
    throw new Error("Invalid attachment reference.");
  }

  const openedWindow = window.open("about:blank", "_blank");

  if (!openedWindow) {
    throw new Error(
      "Your browser blocked the new tab. Allow pop-ups for SecureX and try again."
    );
  }

  try {
    openedWindow.document.title =
      "SecureX — Decrypting attachment";

    openedWindow.document.body.innerHTML = `
      <div style="
        background:#090909;
        color:#f5f5f5;
        min-height:100vh;
        display:flex;
        align-items:center;
        justify-content:center;
        font-family:Arial,sans-serif;
        text-align:center;
      ">
        <div>
          <h2 style="color:#ff3030;">SECUREX</h2>
          <p>Decrypting your attachment securely...</p>
        </div>
      </div>
    `;

    const result =
      await downloadAndDecryptAttachment(attachment);

    if (!result?.objectURL) {
      throw new Error(
        "Unable to decrypt this attachment."
      );
    }

    openedWindow.location.href = result.objectURL;

    return result;
  } catch (error) {
    openedWindow.close();
    throw error;
  }
}

/**
 * Decrypts and downloads an attachment to the device.
 */
export async function saveAttachmentMessage(attachment) {
  if (!attachment?.attachmentId) {
    throw new Error("Invalid attachment reference.");
  }

  const result =
    await downloadAndDecryptAttachment(attachment);

  if (!result?.objectURL) {
    throw new Error(
      "Unable to decrypt or download this attachment."
    );
  }

  const link = document.createElement("a");

  link.href = result.objectURL;

  link.download =
    result.metadata?.name ||
    attachment.name ||
    "SecureX-file";

  document.body.appendChild(link);
  link.click();
  link.remove();

  return result;
}