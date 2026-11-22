// ==================================================
// SECUREX CHAT HELPERS
// ==================================================

// ==================================================
// ICONS
// ==================================================

export function GroupIcon({ size = 18 }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <circle cx="9" cy="8" r="3.5" />
      <path d="M2.5 20v-1.5A5 5 0 0 1 7.5 13.5h3A5 5 0 0 1 15.5 18.5V20" />
      <path d="M16 4.8a3.5 3.5 0 0 1 0 6.8" />
      <path d="M18 14a4.5 4.5 0 0 1 3.5 4.4V20" />
    </svg>
  );
}

export function GroupAddIcon({ size = 21 }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <circle cx="8.5" cy="7.5" r="3.5" />
      <path d="M2 20v-1.5A5 5 0 0 1 7 13.5h3A5 5 0 0 1 15 18.5V20" />
      <path d="M16 5.5a3.5 3.5 0 0 1 0 6.5" />
      <path d="M19 15v6" />
      <path d="M16 18h6" />
    </svg>
  );
}

export function LogoutIcon({ size = 17 }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M10 17l5-5-5-5" />
      <path d="M15 12H3" />
      <path d="M12 3h6a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-6" />
    </svg>
  );
}

export function LinkIcon({ size = 15 }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M10 13a5 5 0 0 0 7.07 0l3-3A5 5 0 0 0 13 2.93l-1.72 1.72" />
      <path d="M14 11a5 5 0 0 0-7.07 0l-3 3A5 5 0 0 0 11 21.07l1.72-1.72" />
    </svg>
  );
}

// ==================================================
// ID AND USER HELPERS
// ==================================================

export function getId(value) {
  if (value === null || value === undefined) return "";

  if (typeof value === "string") return value.trim();

  if (typeof value === "number") return String(value);

  if (typeof value === "object") {
    const id =
      value._id ??
      value.id ??
      value.userId ??
      value.conversationId ??
      value.$oid ??
      "";

    if (id && typeof id === "object") {
      return getId(id);
    }

    return String(id);
  }

  return "";
}

export function normalizeEmail(email = "") {
  return String(email).trim().toLowerCase();
}

export function getCurrentUserDetails(session) {
  const user =
    session?.user ||
    session?.currentUser ||
    session?.profile ||
    {};

  const email = normalizeEmail(
    user.email ||
    session?.email ||
    ""
  );

  return {
    id: getId(
      user._id ||
      user.id ||
      user.userId ||
      session?.userId ||
      session?.id
    ),

    name:
      user.name ||
      user.fullName ||
      user.username ||
      user.displayName ||
      session?.name ||
      "",

    email,

    publicKey:
      user.publicKey ||
      session?.publicKey ||
      "",
  };
}

// ==================================================
// CONVERSATION HELPERS
// ==================================================

export function isGroupConversation(conversation) {
  if (!conversation) return false;

  return (
    conversation.type === "group" ||
    conversation.isGroup === true ||
    conversation.group === true ||
    conversation.conversationType === "group"
  );
}

export function getOtherParticipant(conversation, currentUserId) {
  if (!conversation) return null;

  const participants = conversation.participants || [];
  const myId = getId(currentUserId);

  return (
    participants.find(
      (participant) => getId(participant) !== myId
    ) || null
  );
}

// ==================================================
// GROUP ADMIN CHECK
// Supports promoted admins and legacy admin fields.
// ==================================================

export function isGroupAdmin(conversation, currentUserId) {
  if (!conversation || !currentUserId) return false;

  const myId = getId(currentUserId);

  if (!myId) return false;

  // 1. Check the groupAdmins array.
  // This supports both ObjectIds and populated user objects.

  const groupAdminIds = Array.isArray(conversation.groupAdmins)
    ? conversation.groupAdmins
        .map((admin) => getId(admin))
        .filter(Boolean)
    : [];

  if (groupAdminIds.length > 0) {
    return groupAdminIds.includes(myId);
  }

  // 2. Check legacy groupAdmin/admin fields.

  const legacyAdminId = getId(
    conversation.groupAdmin ||
    conversation.admin
  );

  if (legacyAdminId) {
    return legacyAdminId === myId;
  }

  // 3. Check group creator.

  const creatorId = getId(conversation.createdBy);

  if (creatorId) {
    return creatorId === myId;
  }

  // 4. Final fallback: participant role.

  const currentParticipant = (
    conversation.participants || []
  ).find(
    (participant) => getId(participant) === myId
  );

  return (
    currentParticipant?.role === "admin" ||
    currentParticipant?.isAdmin === true
  );
}

// ==================================================
// CONVERSATION TITLE
// ==================================================

export function getConversationTitle(conversation, currentUserId) {
  if (!conversation) return "Conversation";

  if (isGroupConversation(conversation)) {
    return (
      conversation.name ||
      conversation.groupName ||
      "SecureX Group"
    );
  }

  const person = getOtherParticipant(
    conversation,
    currentUserId
  );

  return (
    person?.name ||
    person?.fullName ||
    person?.username ||
    person?.email ||
    "Unknown user"
  );
}

export function getConversationSubtitle(conversation, currentUserId) {
  if (!conversation) return "";

  if (isGroupConversation(conversation)) {
    const count = conversation.participants?.length || 0;
    return `${count} members`;
  }

  const person = getOtherParticipant(
    conversation,
    currentUserId
  );

  return person?.email || "";
}

// ==================================================
// MESSAGE SENDER HELPERS
// ==================================================

export function getMessageSender(message) {
  if (!message) return "";

  return getId(
    message.sender ||
    message.senderId ||
    message.user ||
    message.userId ||
    message.createdBy
  );
}

/*
 * IMPORTANT:
 * Supports both:
 * isOwnMessage(message, "USER_ID")
 *
 * and:
 * isOwnMessage(message, { id: "USER_ID" })
 *
 * This fixes the alignment bug in ChatLayout.jsx.
 */

export function isOwnMessage(message, currentUser) {
  const senderId = getMessageSender(message);

  const currentUserId =
    typeof currentUser === "string" ||
    typeof currentUser === "number"
      ? getId(currentUser)
      : getId(
          currentUser?.id ||
          currentUser?._id ||
          currentUser?.userId
        );

  return Boolean(
    senderId &&
    currentUserId &&
    senderId === currentUserId
  );
}

export function getMessageSenderName(
  message,
  conversation,
  currentUser
) {
  if (!message) return "User";

  if (isOwnMessage(message, currentUser)) {
    return (
      currentUser?.name ||
      currentUser?.fullName ||
      currentUser?.username ||
      currentUser?.displayName ||
      "You"
    );
  }

  // First check whether the message contains a populated sender.

  const populatedSender =
    message.sender ||
    message.user ||
    message.createdBy;

  if (populatedSender && typeof populatedSender === "object") {
    const populatedName =
      populatedSender.name ||
      populatedSender.fullName ||
      populatedSender.username ||
      populatedSender.displayName ||
      populatedSender.email;

    if (populatedName) return populatedName;
  }

  // Then check the conversation participants.

  const senderId = getMessageSender(message);

  const sender = (
    conversation?.participants || []
  ).find(
    (participant) => getId(participant) === senderId
  );

  return (
    sender?.name ||
    sender?.fullName ||
    sender?.username ||
    sender?.displayName ||
    sender?.email ||
    "Group member"
  );
}

// ==================================================
// CONVERSATION ACTIVITY AND SORTING
// ==================================================

export function getConversationActivity(conversation) {
  if (!conversation) return 0;

  const activity =
    conversation.lastMessageAt ||
    conversation.updatedAt ||
    conversation.createdAt;

  const timestamp = new Date(activity || 0).getTime();

  return Number.isNaN(timestamp) ? 0 : timestamp;
}

export function sortConversations(conversations = []) {
  return [...conversations].sort(
    (a, b) =>
      getConversationActivity(b) -
      getConversationActivity(a)
  );
}

// ==================================================
// UNREAD AND MESSAGE COUNTS
// ==================================================

export function getUnreadCount(conversation) {
  if (!conversation) return 0;

  const value = Number(
    conversation.unreadCount ??
    conversation.unreadMessages ??
    0
  );

  return Number.isFinite(value)
    ? Math.max(0, value)
    : 0;
}

export function getTotalMessageCount(conversation) {
  if (!conversation) return 0;

  const value = Number(
    conversation.messageCount ??
    conversation.totalMessages ??
    conversation.messagesCount ??
    0
  );

  return Number.isFinite(value)
    ? Math.max(0, value)
    : 0;
}

// ==================================================
// SIDEBAR MESSAGE PREVIEW
// ==================================================

export function getSidebarPreview(conversation) {
  if (!conversation) return "No messages yet";

  const message =
    conversation.lastMessage ||
    conversation.latestMessage ||
    null;

  const preview =
    conversation.lastMessagePreview ||
    conversation.lastMessageText ||
    message?.preview ||
    message?.text ||
    "";

  const type =
    message?.type ||
    conversation.lastMessageType ||
    "text";

  if (type === "image") return "▧ Photo";
  if (type === "video") return "▶ Video";
  if (type === "audio") return "♫ Audio";

  if (type === "file" || type === "document") {
    return "▤ Attachment";
  }

  if (typeof preview === "string" && preview.trim()) {
    return preview;
  }

  return conversation.lastMessageAt
    ? "Encrypted message"
    : "No messages yet";
}

// ==================================================
// TIME FORMATTERS
// ==================================================

export function formatTime(date) {
  if (!date) return "";

  const parsed = new Date(date);

  if (Number.isNaN(parsed.getTime())) return "";

  return parsed.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatSidebarTime(date) {
  if (!date) return "";

  const parsed = new Date(date);

  if (Number.isNaN(parsed.getTime())) return "";

  const now = new Date();

  const sameDay =
    parsed.getDate() === now.getDate() &&
    parsed.getMonth() === now.getMonth() &&
    parsed.getFullYear() === now.getFullYear();

  if (sameDay) {
    return parsed.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });
  }

  const yesterday = new Date();
  yesterday.setDate(yesterday.getDate() - 1);

  const isYesterday =
    parsed.getDate() === yesterday.getDate() &&
    parsed.getMonth() === yesterday.getMonth() &&
    parsed.getFullYear() === yesterday.getFullYear();

  if (isYesterday) return "Yesterday";

  const daysDifference = Math.floor(
    (now.getTime() - parsed.getTime()) /
    (1000 * 60 * 60 * 24)
  );

  if (daysDifference < 7) {
    return parsed.toLocaleDateString([], {
      weekday: "short",
    });
  }

  return parsed.toLocaleDateString([], {
    day: "2-digit",
    month: "short",
  });
}

// ==================================================
// SECURE LINK HELPERS
// ==================================================

const URL_PATTERN =
  /((?:https?:\/\/|www\.)[^\s<>"']+)/gi;

export function normalizeLink(value = "") {
  let url = String(value).trim();

  if (!url) return "";

  if (url.startsWith("www.")) {
    url = `https://${url}`;
  }

  try {
    const parsed = new URL(url);

    if (
      parsed.protocol !== "http:" &&
      parsed.protocol !== "https:"
    ) {
      return "";
    }

    return parsed.href;
  } catch {
    return "";
  }
}

export function isSuspiciousLink(value = "") {
  const normalized = normalizeLink(value);

  if (!normalized) return true;

  try {
    const url = new URL(normalized);
    const hostname = url.hostname.toLowerCase();

    const suspiciousPatterns = [
      /@/,
      /\d{1,3}(?:\.\d{1,3}){3}/,
      /xn--/,
      /login.*verify/,
      /secure.*account/,
      /account.*verify/,
    ];

    if (
      hostname === "localhost" ||
      hostname.endsWith(".localhost") ||
      hostname === "127.0.0.1"
    ) {
      return true;
    }

    return suspiciousPatterns.some(
      (pattern) => pattern.test(hostname)
    );
  } catch {
    return true;
  }
}

export function getLinkParts(text = "") {
  if (!text) return [];

  const safeText = String(text);
  const parts = [];
  let lastIndex = 0;

  const matches = [...safeText.matchAll(URL_PATTERN)];

  for (const match of matches) {
    const rawValue = match[0];
    const index = match.index;

    if (index > lastIndex) {
      parts.push({
        type: "text",
        value: safeText.slice(lastIndex, index),
      });
    }

    const cleanedValue = rawValue.replace(/[),.!?;:]+$/, "");
    const trailingText = rawValue.slice(cleanedValue.length);

    const url = normalizeLink(cleanedValue);

    if (url) {
      let hostname = "";

      try {
        hostname = new URL(url).hostname;
      } catch {
        hostname = cleanedValue;
      }

      parts.push({
        type: "link",
        value: cleanedValue,
        url,
        hostname,
        suspicious: isSuspiciousLink(url),
      });
    } else {
      parts.push({
        type: "text",
        value: cleanedValue,
      });
    }

    if (trailingText) {
      parts.push({
        type: "text",
        value: trailingText,
      });
    }

    lastIndex = index + rawValue.length;
  }

  if (lastIndex < safeText.length) {
    parts.push({
      type: "text",
      value: safeText.slice(lastIndex),
    });
  }

  return parts;
}