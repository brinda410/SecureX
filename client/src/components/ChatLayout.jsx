import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  getMyConversations,
  createConversation,
  markConversationRead,
} from "../services/conversationService.js";

import {
  sendEncryptedMessage,
  getEncryptedMessages,
} from "../services/messageService.js";

import {
  encryptMessageForRecipient,
  encryptMessageForGroup,
  decryptStoredMessage,
} from "../utils/messageEncryption.js";

import {
  getCryptoSession,
  clearCryptoSession,
} from "../utils/cryptoSession.js";

import {
  connectSocket,
  disconnectSocket,
  joinConversation,
  leaveConversation,
  sendTyping,
  stopTyping,
  subscribeToEvent,
} from "../services/socket.js";

import {
  sendAttachmentMessage,
  saveAttachmentMessage,
} from "../services/attachmentMessageService.js";

import {
  downloadAndDecryptAttachment,
} from "../services/attachmentWorkflow.js";

import GroupChatModal from "./GroupChatModal.jsx";
import GroupManagementPanel from "./GroupManagementPanel.jsx";
import SecurityCommandCenter from "./SecurityCommandCenter.jsx";
import React from "react";
import { fetchUserPublicKey } from "../utils/publicKeyService.js";

import {
  getId,
  normalizeEmail,
  sortConversations,
  getConversationTitle,
  getConversationSubtitle,
  getCurrentUserDetails,
  getMessageSenderName,
  getOtherParticipant,
  isOwnMessage,
  formatTime,
  formatSidebarTime,
  isGroupConversation,
  isGroupAdmin,
  getSidebarPreview,
  getUnreadCount,
} from "../utils/chatHelpers.jsx";

const API_URL = "http://localhost:5000/api";
const MAX_FILE_SIZE = 25 * 1024 * 1024;
const ATTACHMENT_PREFIX = "SECUREX_ATTACHMENT::";
const REPLY_PREFIX = "SECUREX_REPLY::";

/* =======================================================
   GENERAL HELPERS
======================================================= */

const toDisplayText = (value) => {
  if (value === null || value === undefined) return "";

  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return String(value);
  }

  if (Array.isArray(value)) {
    return value.map(toDisplayText).filter(Boolean).join(", ");
  }

  if (typeof value === "object") {
    for (const item of [
      value.text,
      value.content,
      value.message,
      value.plaintext,
      value.name,
      value.email,
      value.value,
    ]) {
      if (item !== undefined && item !== null) {
        const result = toDisplayText(item);
        if (result) return result;
      }
    }
  }

  return "";
};

const getSafeError = (error, fallback) =>
  toDisplayText(error?.message) || fallback;

const getConversationId = (conversation) => {
  if (typeof conversation === "string" || typeof conversation === "number") {
    return String(conversation);
  }

  const id =
    conversation?._id ??
    conversation?.conversationId ??
    conversation?.id;

  if (!id) return null;

  return String(
    typeof id === "object" ? id._id ?? id.toString() : id
  );
};

const normalizeMessage = (message, plaintext, failed = false) => ({
  ...message,
  plaintext: toDisplayText(plaintext),
  decryptionFailed: failed,
});

const upsertMessage = (previous, incoming) => {
  const incomingId = getId(incoming);

  if (!incomingId) return previous;

  const index = previous.findIndex(
    (item) => getId(item) === incomingId
  );

  if (index !== -1) {
    return previous.map((item, i) =>
      i === index ? incoming : item
    );
  }

  return [...previous, incoming];
};

const createClientMessageId = () =>
  globalThis.crypto?.randomUUID?.() ||
  `${Date.now()}-${Math.random().toString(16).slice(2)}`;

const getAuthHeaders = () => {
  const session = getCryptoSession();

  if (!session?.token) {
    throw new Error(
      "Your SecureX session has expired. Please log in again."
    );
  }

  return {
    Authorization: `Bearer ${session.token}`,
    "Content-Type": "application/json",
  };
};

const getParticipants = (conversation) => {
  const rawParticipants = conversation?.participants || [];

  const ids = rawParticipants
    .map((participant) => getId(participant))
    .filter(Boolean);

  const session = getCryptoSession();
  const currentUserId = getId(session?.userId);

  console.log("SECUREX GROUP ENCRYPTION CHECK", {
    conversationId: getId(conversation),
    currentUserId,
    participantCount: rawParticipants.length,
    participantIds: ids,
    uniqueParticipantCount: new Set(ids).size,
    senderIncluded: ids.includes(currentUserId),
  });

  return [...new Set(ids)];
};
const getAttachmentInfo = (plaintext) => {
  const text = toDisplayText(plaintext);

  if (!text.startsWith(ATTACHMENT_PREFIX)) return null;

  try {
    const parsed = JSON.parse(
      text.slice(ATTACHMENT_PREFIX.length)
    );

    if (!parsed || typeof parsed !== "object") return null;

    return {
      ...parsed,
      name: toDisplayText(parsed.name) || "Attachment",
      type: toDisplayText(parsed.type),
      size: Number(parsed.size) || 0,
      attachmentId: toDisplayText(parsed.attachmentId),
    };
  } catch {
    return null;
  }
};

const getReplyInfo = (plaintext) => {
  const text = toDisplayText(plaintext);

  if (!text.startsWith(REPLY_PREFIX)) return null;

  try {
    const parsed = JSON.parse(text.slice(REPLY_PREFIX.length));

    if (!parsed || typeof parsed !== "object") return null;

    return {
      text: toDisplayText(parsed.text),
      replyTo: parsed.replyTo || null,
    };
  } catch {
    return null;
  }
};

const getMessagePreview = (message) => {
  if (!message) return "Message unavailable";

  const attachment = getAttachmentInfo(message.plaintext);

  if (attachment) {
    if (attachment.caption) {
      return toDisplayText(attachment.caption).slice(0, 180);
    }

    if (attachment.type?.startsWith("image/")) return "Photo";
    if (attachment.type?.startsWith("video/")) return "Video";
    if (attachment.type?.startsWith("audio/")) return "Audio";
    return attachment.name || "Attachment";
  }

  const reply = getReplyInfo(message.plaintext);
  const text = reply?.text || toDisplayText(message.plaintext);

  return text.slice(0, 180) || "Message";
};

const getMessageText = (message) => {
  const attachment = getAttachmentInfo(message?.plaintext);

  if (attachment) return toDisplayText(attachment.caption);

  const reply = getReplyInfo(message?.plaintext);

  return reply
    ? reply.text
    : toDisplayText(message?.plaintext);
};

const formatFileSize = (bytes = 0) => {
  const size = Number(bytes);

  if (!Number.isFinite(size) || size <= 0) return "0 B";

  const units = ["B", "KB", "MB", "GB"];

  const index = Math.min(
    Math.floor(Math.log(size) / Math.log(1024)),
    units.length - 1
  );

  return `${(size / Math.pow(1024, index)).toFixed(1)} ${units[index]}`;
};

const getFileIcon = (type = "") => {
  const safeType = toDisplayText(type).toLowerCase();

  if (safeType.startsWith("image/")) return "▧";
  if (safeType.startsWith("video/")) return "▶";
  if (safeType.startsWith("audio/")) return "♫";
  if (safeType.includes("pdf")) return "PDF";
  if (safeType.includes("word")) return "DOC";
  if (safeType.includes("spreadsheet")) return "XLS";

  return "FILE";
};

const getMediaCategory = (type = "") => {
  const safeType = toDisplayText(type).toLowerCase();

  if (safeType.startsWith("image/")) return "image";
  if (safeType.startsWith("video/")) return "video";
  if (safeType.startsWith("audio/")) return "audio";
  if (safeType.includes("pdf")) return "pdf";

  return "document";
};

const getRecordingMimeType = (kind) => {
  if (typeof MediaRecorder === "undefined") return "";

  const candidates = kind === "video"
    ? [
        "video/webm;codecs=vp9,opus",
        "video/webm;codecs=vp8,opus",
        "video/webm",
      ]
    : [
        "audio/webm;codecs=opus",
        "audio/webm",
        "audio/ogg;codecs=opus",
        "audio/ogg",
      ];

  return candidates.find((type) =>
    MediaRecorder.isTypeSupported(type)
  ) || "";
};
const formatRecordingTime = (seconds = 0) => {
  const totalSeconds = Math.max(0, Math.floor(Number(seconds) || 0));
  const minutes = Math.floor(totalSeconds / 60);
  const remainingSeconds = totalSeconds % 60;

  return `${String(minutes).padStart(2, "0")}:${String(remainingSeconds).padStart(2, "0")}`;
};

const getSystemEventPersonName = (person, fallback = "A member") => {
  if (!person) return fallback;

  if (typeof person === "string") return fallback;

  return (
    toDisplayText(
      person.name ||
      person.fullName ||
      person.displayName ||
      person.username ||
      person.email
    ) || fallback
  );
};

const getSystemEventText = (message) => {
  const event = message?.systemEvent || {};
  const actor = getSystemEventPersonName(event.actorId, "A member");
  const target = getSystemEventPersonName(event.targetUserId, "a member");
  const previousAdmin = getSystemEventPersonName(
    event.previousAdminId,
    "the previous admin"
  );
  const newAdmin = getSystemEventPersonName(
    event.newAdminId,
    "the new admin"
  );

  switch (event.type) {
    case "group_created":
      return `${actor} created the group`;
    case "member_added":
      return `${actor} added ${target}`;
    case "member_removed":
      return `${actor} removed ${target}`;
    case "member_left":
      return `${actor} left the group`;
    case "admin_changed":
      return `${actor} changed the group admin from ${previousAdmin} to ${newAdmin}`;
    default:
      return "Group activity";
  }
};

/* =======================================================
   ICONS
======================================================= */

const GroupIcon = () => (
  <svg
    viewBox="0 0 24 24"
    width="21"
    height="21"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <path d="M16 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
    <circle cx="10" cy="7" r="4" />
    <path d="M20 21v-2a4 4 0 0 0-3-3.87" />
    <path d="M16 3.13a4 4 0 0 1 0 7.75" />
  </svg>
);

const GroupAddIcon = () => (
  <svg
    viewBox="0 0 24 24"
    width="21"
    height="21"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <path d="M16 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
    <circle cx="10" cy="7" r="4" />
    <path d="M19 8v6M16 11h6" />
  </svg>
);

/* =======================================================
   CLICKABLE LINKS
======================================================= */

const renderMessageWithLinks = (text) => {
  const safeText = toDisplayText(text);

  const urlRegex =
    /(https?:\/\/[^\s<>"']+|www\.[^\s<>"']+)/gi;

  return safeText.split(urlRegex).map((part, index) => {
    if (!part) return null;

    if (!/^(https?:\/\/|www\.)/i.test(part)) {
      return part;
    }

    const href = part.startsWith("www.")
      ? `https://${part}`
      : part;

    return (
      <a
        key={`${index}-${part}`}
        href={href}
        target="_blank"
        rel="noopener noreferrer"
        className="sx-message-link"
      >
        {part}
      </a>
    );
  });
};

/* =======================================================
   MAIN COMPONENT
======================================================= */

function ChatLayout({ onLogout }) {
  const session = getCryptoSession();

  const currentUser = useMemo(
    () => getCurrentUserDetails(session),
    []
  );

  const currentUserId = getId(
    currentUser?.id || session?.userId
  );

  const currentUserName =
    currentUser?.name ||
    currentUser?.fullName ||
    currentUser?.username ||
    currentUser?.displayName ||
    session?.user?.name ||
    session?.name ||
    currentUser?.email ||
    "SecureX User";

  const currentUserEmail =
    currentUser?.email ||
    session?.user?.email ||
    session?.email ||
    "";

  const currentUserInitial =
    toDisplayText(currentUserName).trim().charAt(0).toUpperCase() ||
    "U";

  const [conversations, setConversations] = useState([]);
  const [selectedChat, setSelectedChat] = useState(null);
  const [messages, setMessages] = useState([]);

  const [search, setSearch] = useState("");
  const [messageText, setMessageText] = useState("");

  const [loading, setLoading] = useState(true);
  const [messagesLoading, setMessagesLoading] = useState(false);
  const [sending, setSending] = useState(false);
  const [uploading, setUploading] = useState(false);

  const [error, setError] = useState("");
  const [typingUser, setTypingUser] = useState("");

  const [showNewChat, setShowNewChat] = useState(false);
  const [newChatEmail, setNewChatEmail] = useState("");
  const [creatingChat, setCreatingChat] = useState(false);

  const [showGroupModal, setShowGroupModal] = useState(false);
  const [groupModalConversation, setGroupModalConversation] =
    useState(null);
  const [showGroupInfo, setShowGroupInfo] = useState(false);

  const [editingMessageId, setEditingMessageId] = useState(null);
  const [editingText, setEditingText] = useState("");
  const [savingEdit, setSavingEdit] = useState(false);

  const [activeMenuId, setActiveMenuId] = useState(null);
  const [securityOpen, setSecurityOpen] = useState(false);
  const [showSecurityDashboard, setShowSecurityDashboard] = useState(false);
  const [contactKeyInfo, setContactKeyInfo] = useState(null);
const [sharedFingerprint, setSharedFingerprint] = useState("");
const [keyTrustStatus, setKeyTrustStatus] = useState("LOADING");
// SecureX group member fingerprint verification
const [groupKeyInfos, setGroupKeyInfos] = useState([]);
const [groupFingerprints, setGroupFingerprints] = useState({});
const [groupKeyLoading, setGroupKeyLoading] = useState(false);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(true);
  const [socketConnected, setSocketConnected] = useState(false);

  const [attachmentPreview, setAttachmentPreview] = useState(null);
  const [previewLoadingId, setPreviewLoadingId] = useState(null);

  // New message/reply/attachment states.
  const [replyingTo, setReplyingTo] = useState(null);
  const [pendingAttachment, setPendingAttachment] = useState(null);
  const [attachmentCaption, setAttachmentCaption] = useState("");
    // Live camera preview states.
  const [showCameraPreview, setShowCameraPreview] = useState(false);
  const [cameraStream, setCameraStream] = useState(null);
  const [cameraFacingMode, setCameraFacingMode] = useState("user");
  const [capturedPhoto, setCapturedPhoto] = useState(null);

  const cameraVideoRef = useRef(null);
  const cameraStreamRef = useRef(null);

  // Recording states.
  const [recordingType, setRecordingType] = useState(null);
  const [isRecording, setIsRecording] = useState(false);
  const [recordingSeconds, setRecordingSeconds] = useState(0);
  const [recordingError, setRecordingError] = useState("");
  const [showCameraMenu, setShowCameraMenu] = useState(false);

  const messagesEndRef = useRef(null);
  const messagesContainerRef = useRef(null);
  const messageInputRef = useRef(null);
  const attachmentInputRef = useRef(null);

  const selectedChatRef = useRef(null);
  const typingTimeoutRef = useRef(null);

  const shouldAutoScrollRef = useRef(true);
  const forceNextScrollRef = useRef(false);
  const scrollFrameRef = useRef(null);

  const mediaRecorderRef = useRef(null);
  const recordingStreamRef = useRef(null);
  const recordingChunksRef = useRef([]);
  const recordingCancelledRef = useRef(false);
  const recordingTimerRef = useRef(null);

  const selectedId = getConversationId(selectedChat);
  const selectedIsGroup = isGroupConversation(selectedChat);

  // =====================================================
// CONTACT PUBLIC KEY VERIFICATION
// =====================================================

const otherParticipant = selectedChat && !selectedIsGroup
  ? getOtherParticipant(selectedChat, currentUserId)
  : null;

const otherParticipantId = getId(otherParticipant);

useEffect(() => {
  let cancelled = false;

  const loadContactKey = async () => {
    setContactKeyInfo(null);
    setSharedFingerprint("");

    if (!otherParticipantId) {
      setKeyTrustStatus("UNAVAILABLE");
      return;
    }

    setKeyTrustStatus("LOADING");

    try {
      const keyData = await fetchUserPublicKey(otherParticipantId);

      if (cancelled) return;

      const storageKey =
        `securex_verified_key_${currentUserId}_${otherParticipantId}`;

      const savedTrust = localStorage.getItem(storageKey);
      const previous = savedTrust ? JSON.parse(savedTrust) : null;

      setContactKeyInfo(keyData);

      if (
        previous?.verified === true &&
        previous.fingerprint !== keyData.fingerprint
      ) {
        setKeyTrustStatus("CHANGED");
      } else if (
        previous?.verified === true &&
        previous.fingerprint === keyData.fingerprint
      ) {
        setKeyTrustStatus("VERIFIED");
      } else {
        setKeyTrustStatus("UNVERIFIED");
      }

    } catch (error) {
      console.error("Contact key verification failed:", error);
      if (!cancelled) setKeyTrustStatus("ERROR");
    }
  };

  loadContactKey();

  return () => {
    cancelled = true;
  };

}, [otherParticipantId, currentUserId]);

  const selectedIsAdmin =
    selectedChat && isGroupAdmin(selectedChat, currentUserId);

  useEffect(() => {
    selectedChatRef.current = selectedChat;
  }, [selectedChat]);
// Fetch and validate public keys for every group member
useEffect(() => {
  let cancelled = false;

  const loadGroupKeys = async () => {
    if (!selectedChat || !selectedIsGroup || !currentUserId) {
      setGroupKeyInfos([]);
      return;
    }

    setGroupKeyLoading(true);

    try {
      const memberIds = getParticipants(selectedChat)
        .filter((id) => id !== getId(currentUserId));

      const results = await Promise.all(
        memberIds.map(async (memberId) => {
          try {
            const keyInfo = await fetchUserPublicKey(memberId);

            const storageKey =
              `securex_verified_key_${currentUserId}_${memberId}`;

            const saved = JSON.parse(
              localStorage.getItem(storageKey) || "null"
            );

            let status = "UNVERIFIED";

            if (saved?.verified) {
              status =
                saved.fingerprint === keyInfo.fingerprint
                  ? "VERIFIED"
                  : "CHANGED";
            }

            return {
              userId: memberId,
              name: keyInfo.name || "Group member",
              fingerprint: keyInfo.fingerprint,
              keyVersion: keyInfo.keyVersion,
              status
            };
          } catch (error) {
  console.error(
    "SECUREX GROUP MEMBER KEY ERROR:",
    memberId,
    error.message
  );

  return {
    userId: memberId,
    name: `Member ${String(memberId).slice(-6)}`,
    fingerprint: null,
    status: "ERROR",
    error: error.message
  };
}
        })
      );

      if (!cancelled) {
        setGroupKeyInfos(results);
      }
    } finally {
      if (!cancelled) {
        setGroupKeyLoading(false);
      }
    }
  };

  loadGroupKeys();

  return () => {
    cancelled = true;
  };
}, [selectedId, selectedIsGroup, currentUserId]);
 /* =====================================================
   RECORDING CLEANUP
===================================================== */

const stopRecordingTracks = useCallback(() => {
  if (recordingTimerRef.current) {
    clearInterval(recordingTimerRef.current);
    recordingTimerRef.current = null;
  }

  if (recordingStreamRef.current) {
    recordingStreamRef.current
      .getTracks()
      .forEach((track) => track.stop());

    recordingStreamRef.current = null;
  }

  mediaRecorderRef.current = null;
  recordingChunksRef.current = [];
  setIsRecording(false);
  setRecordingType(null);
  setRecordingSeconds(0);
  setCameraStream(null);
setShowCameraPreview(false);

if (cameraVideoRef.current) {
  cameraVideoRef.current.srcObject = null;
}
}, []);

useEffect(() => {
  return () => {
    // Stop recording timer
    if (recordingTimerRef.current) {
      clearInterval(recordingTimerRef.current);
    }

    // Stop recording stream
    if (recordingStreamRef.current) {
      recordingStreamRef.current
        .getTracks()
        .forEach((track) => track.stop());
    }

    // Stop live camera stream
    if (cameraStreamRef.current) {
      cameraStreamRef.current
        .getTracks()
        .forEach((track) => track.stop());
    }

    // Cancel scrolling animation
    if (scrollFrameRef.current) {
      cancelAnimationFrame(scrollFrameRef.current);
    }
  };
}, []);


/* =====================================================
   PREVIEW URL CLEANUP
===================================================== */

const closeAttachmentPreview = useCallback(() => {
  setAttachmentPreview((current) => {
    if (current?.url) URL.revokeObjectURL(current.url);
    return null;
  });
}, []);

useEffect(() => {
  return () => {
    if (attachmentPreview?.url) {
      URL.revokeObjectURL(attachmentPreview.url);
    }
  };
}, [attachmentPreview]);

useEffect(() => {
  const handleEscape = (event) => {
    if (event.key === "Escape") {
      closeAttachmentPreview();
      setActiveMenuId(null);
    }
  };

  window.addEventListener("keydown", handleEscape);

  return () => {
    window.removeEventListener("keydown", handleEscape);
  };
}, [closeAttachmentPreview]);
  /* =====================================================
     WHATSAPP-STYLE SCROLLING
  ===================================================== */

  const scrollToBottom = useCallback((force = false) => {
    if (!force && !shouldAutoScrollRef.current) return;

    if (scrollFrameRef.current) {
      cancelAnimationFrame(scrollFrameRef.current);
    }

    scrollFrameRef.current = requestAnimationFrame(() => {
      const container = messagesContainerRef.current;

      if (!container) return;

      container.scrollTo({
        top: container.scrollHeight,
        behavior: "smooth",
      });

      messagesEndRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "end",
      });
    });
  }, []);

  useEffect(() => {
    if (messagesLoading) return;

    if (forceNextScrollRef.current) {
      forceNextScrollRef.current = false;
      shouldAutoScrollRef.current = true;
      scrollToBottom(true);
      return;
    }

    if (shouldAutoScrollRef.current) {
      scrollToBottom();
    }
  }, [messages, messagesLoading, scrollToBottom]);

  /* =====================================================
     JUMP TO REPLIED MESSAGE
  ===================================================== */

  const jumpToMessage = useCallback((messageId) => {
    if (!messageId) return;

    const target = document.getElementById(
      `sx-message-${messageId}`
    );

    if (!target) {
      setError("The original message is no longer available.");
      return;
    }

    target.scrollIntoView({
      behavior: "smooth",
      block: "center",
    });

    target.classList.add("sx-message-highlight");

    window.setTimeout(() => {
      target.classList.remove("sx-message-highlight");
    }, 1800);
  }, []);

  const getReplyReference = (message) => ({
    messageId: getId(message),
    senderName: getMessageSenderName(
      message,
      selectedChat,
      currentUser
    ),
    preview: getMessagePreview(message),
  });

  /* =====================================================
      CONVERSATIONS
  ===================================================== */

  const refreshConversations = useCallback(async () => {
    try {
      const data = await getMyConversations();
      const safeData = Array.isArray(data) ? data : [];

      setConversations(sortConversations(safeData));

      return safeData;
    } catch (err) {
      setError(
        getSafeError(err, "Unable to load conversations.")
      );

      return [];
    }
  }, []);

  useEffect(() => {
    let active = true;

    const load = async () => {
      setLoading(true);

      try {
        const data = await getMyConversations();

        if (active) {
          setConversations(
            sortConversations(Array.isArray(data) ? data : [])
          );
        }
      } catch (err) {
        if (active) {
          setError(
            getSafeError(err, "Unable to load conversations.")
          );
        }
      } finally {
        if (active) setLoading(false);
      }
    };

    load();

    return () => {
      active = false;
    };
  }, []);

  /* =====================================================
     MESSAGE DECRYPTION
  ===================================================== */
const decryptMessages = useCallback(async (storedMessages) => {
  return Promise.all(
    (Array.isArray(storedMessages) ? storedMessages : []).map(
      async (message) => {
        if (message?.messageType === "system") {
          return normalizeMessage(message, "");
        }

        try {
          const plaintext = await decryptStoredMessage(message);
          return normalizeMessage(message, plaintext);
        } catch {
          return normalizeMessage(message, "", true);
        }
      }
    )
  );
}, []);
/* =====================================================
   LOAD AND DECRYPT CONVERSATION MESSAGES
===================================================== */

const loadMessages = useCallback(async (conversationId) => {
  if (!conversationId) return;

  try {
    const storedMessages = await getEncryptedMessages(
      String(conversationId)
    );

    const decryptedMessages = await decryptMessages(
      storedMessages
    );

    // Prevent an older request from replacing the
    // messages of a newly selected conversation.
    if (
  getConversationId(selectedChatRef.current) !==
  String(conversationId)
) {
  return;
}
    setMessages(decryptedMessages);

    markConversationRead(conversationId).catch(() => {});

    shouldAutoScrollRef.current = true;
    forceNextScrollRef.current = true;

  } catch (err) {
    console.error("SecureX message loading failed:", err);

    setError(
      getSafeError(
        err,
        "Unable to load conversation messages."
      )
    );
  }
}, [decryptMessages]);
    /* =====================================================
     SELECT CONVERSATION
  ===================================================== */

  const selectConversation = async (conversation) => {
  const nextId = getConversationId(conversation);

  if (!nextId) return;

  try {
    // Verify that the conversation still exists for this user.
    const latest = await getMyConversations();

    const canonicalConversation = latest.find(
      (item) => getConversationId(item) === nextId
    );

    if (!canonicalConversation) {
      await refreshConversations();
      setError("This conversation is no longer available.");
      return;
    }

    const previousId = getConversationId(
      selectedChatRef.current
    );

    if (previousId && previousId !== nextId) {
      leaveConversation(previousId);
    }

    closeAttachmentPreview();

    shouldAutoScrollRef.current = true;
    forceNextScrollRef.current = true;

    setSelectedChat(canonicalConversation);
    selectedChatRef.current = canonicalConversation;

    setMessages([]);
    setTypingUser("");
    setActiveMenuId(null);
    setEditingMessageId(null);
    setReplyingTo(null);
    setPendingAttachment(null);
    setAttachmentCaption("");
    setMobileSidebarOpen(false);
    await joinConversation(nextId);

    // Load previously saved encrypted messages from MongoDB.
    await loadMessages(nextId);

    await refreshConversations();
  } catch (err) {
    console.error("Conversation selection failed:", err);
    setError("Unable to open this conversation.");
  }
};

  /* =====================================================
     SOCKET.IO
  ===================================================== */

  useEffect(() => {
    if (!session?.token) return;

    let mounted = true;
    let socket;

    try {
      socket = connectSocket(session.token);

      const updateConnection = () => {
        if (!mounted) return;

        setSocketConnected(true);

        const activeConversationId = getConversationId(
            selectedChatRef.current
      );

        if (activeConversationId) {
          joinConversation(activeConversationId).catch(() => {});
        }
      };

      const updateDisconnection = () => {
        if (mounted) setSocketConnected(false);
      };

      socket.on("connect", updateConnection);
      socket.on("disconnect", updateDisconnection);

      setSocketConnected(Boolean(socket.connected));

      const unsubscribeNewMessage = subscribeToEvent(
        "new_encrypted_message",
        async (payload) => {
          const incoming =
            payload?.message ||
            payload?.data ||
            payload;

    const conversationId =
  getConversationId(payload?.conversationId) ||
  getConversationId(incoming?.conversation);

if (!getId(incoming)) return;

if (
  conversationId ===
  getConversationId(selectedChatRef.current)
) {
try {
  const plaintext =
    incoming?.messageType === "system"
      ? ""
      : await decryptStoredMessage(incoming);

  if (!mounted) return;

  setMessages((previous) =>
    upsertMessage(
      previous,
      normalizeMessage(incoming, plaintext)
    )
  );

  markConversationRead(conversationId).catch(() => {});
  scrollToBottom();
} catch {
  if (!mounted) return;

  setMessages((previous) =>
    upsertMessage(
      previous,
      normalizeMessage(incoming, "", true)
    )
  );
}        }

          refreshConversations();
        }
      );

      const unsubscribeActivity = subscribeToEvent(
        "conversation_activity",
        () => refreshConversations()
      );

      const unsubscribeRead = subscribeToEvent(
        "conversation_read",
        () => refreshConversations()
      );

      const unsubscribeEdited = subscribeToEvent(
        "message_edited",
        async (payload) => {
          const updated =
            payload?.message ||
            payload?.data;

          if (!getId(updated)) return;

          try {
            const plaintext =
              await decryptStoredMessage(updated);

            if (!mounted) return;

            setMessages((previous) =>
              previous.map((message) =>
                getId(message) === getId(updated)
                  ? normalizeMessage(updated, plaintext)
                  : message
              )
            );
          } catch {
            if (!mounted) return;

            setMessages((previous) =>
              previous.map((message) =>
                getId(message) === getId(updated)
                  ? normalizeMessage(updated, "", true)
                  : message
              )
            );
          }
        }
      );

      const unsubscribeDeleted = subscribeToEvent(
        "message_deleted_for_everyone",
        (payload) => {
          const messageId = getId(
            payload?.messageId ||
            payload?._id ||
            payload?.message
          );

          if (!messageId) return;

          setMessages((previous) =>
            previous.filter(
              (message) => getId(message) !== messageId
            )
          );
        }
      );

      const unsubscribeDeletedForMe = subscribeToEvent(
        "message_deleted_for_me",
        (payload) => {
          const messageId = getId(
            payload?.messageId ||
            payload?._id ||
            payload?.message
          );

          if (!messageId) return;

          setMessages((previous) =>
            previous.filter(
              (message) => getId(message) !== messageId
            )
          );
        }
      );

      const unsubscribeTyping = subscribeToEvent(
        "user_typing",
        (payload) => {
          if (
            getId(payload?.conversationId) !==
            getConversationId(selectedChatRef.current)
          ) {
            return;
          }

          const name =
            payload?.userName ||
            payload?.name ||
            "Someone";

          setTypingUser(name);
        }
      );

      const unsubscribeStoppedTyping = subscribeToEvent(
        "user_stopped_typing",
        (payload) => {
          if (
            getId(payload?.conversationId) ===
            getConversationId(selectedChatRef.current)
          ) {
            setTypingUser("");
          }
        }
      );

      return () => {
        mounted = false;

        socket?.off("connect", updateConnection);
        socket?.off("disconnect", updateDisconnection);

        unsubscribeNewMessage?.();
        unsubscribeActivity?.();
        unsubscribeRead?.();
        unsubscribeEdited?.();
        unsubscribeDeleted?.();
        unsubscribeDeletedForMe?.();
        unsubscribeTyping?.();
        unsubscribeStoppedTyping?.();

        disconnectSocket();
      };
    } catch (err) {
      console.error("SecureX socket error:", err);
      setSocketConnected(false);
    }

    return () => {
      mounted = false;
      disconnectSocket();
    };
  }, [session?.token, refreshConversations, scrollToBottom]);

  /* =====================================================
     LOGOUT
  ===================================================== */

  const handleLogout = () => {
    stopRecordingTracks();
    closeAttachmentPreview();

    if (selectedId) {
      leaveConversation(selectedId);
    }

    disconnectSocket();
    clearCryptoSession();

    if (typeof onLogout === "function") {
      onLogout();
    } else {
      window.location.href = "/";
    }
  };

  /* =====================================================
     SEND ENCRYPTED TEXT / REPLY
  ===================================================== */

  const handleSendMessage = async (event) => {
    event?.preventDefault();

    const text = messageText.trim();

    if (
      !text ||
      !selectedChat ||
      sending ||
      uploading ||
      pendingAttachment
    ) {
      return;
    }

    if (!checkContactTrustBeforeSend()) {
  return;
}

setSending(true);
setError("");

const clientMessageId = createClientMessageId();

try {
      let plaintext = text;

      // Reply metadata is placed inside the encrypted plaintext.
      // It is never sent as a separate plaintext database field.
      if (replyingTo) {
        const replyEnvelope = {
          text,
          replyTo: getReplyReference(replyingTo),
        };

        plaintext =
          REPLY_PREFIX + JSON.stringify(replyEnvelope);
      }

      let encryptedPayload;

      if (selectedIsGroup) {
        encryptedPayload = await encryptMessageForGroup(
          plaintext,
          getParticipants(selectedChat),
          clientMessageId,
          selectedId
        );
      } else {
        const recipient = getOtherParticipant(
          selectedChat,
          currentUserId
        );

        const recipientId = getId(recipient);

        if (!recipientId) {
          throw new Error("Unable to identify the recipient.");
        }

        encryptedPayload = await encryptMessageForRecipient(
          plaintext,
          recipientId,
          clientMessageId
        );
      }

      const result = await sendEncryptedMessage(
        selectedId,
        encryptedPayload
      );

      const sentMessage =
        result?.message ||
        result?.data?.message ||
        result?.data;

      if (getId(sentMessage)) {
        setMessages((previous) =>
          upsertMessage(
            previous,
            normalizeMessage(sentMessage, plaintext)
          )
        );
      } else {
        await loadMessages(selectedId);
      }

      setMessageText("");
      setReplyingTo(null);

      stopTyping(selectedId);

      shouldAutoScrollRef.current = true;
      scrollToBottom(true);

      refreshConversations();

      messageInputRef.current?.focus();
    } catch (err) {
      setError(
        getSafeError(err, "Message could not be sent.")
      );
    } finally {
      setSending(false);
    }
  };

  /* =====================================================
     TYPING INDICATOR
  ===================================================== */

  const handleTyping = (value) => {
    setMessageText(value);

    if (!selectedId) return;

    sendTyping(selectedId);

    clearTimeout(typingTimeoutRef.current);

    typingTimeoutRef.current = setTimeout(() => {
      stopTyping(selectedId);
    }, 1200);
  };

  /* =====================================================
     PRIVATE CHAT CREATION
  ===================================================== */

  const handleCreatePrivateChat = async (event) => {
    event.preventDefault();

    const email = normalizeEmail(newChatEmail);

    if (!/^[a-zA-Z0-9._%+-]+@gmail\.com$/.test(email)) {
      setError("Please enter a valid Gmail address.");
      return;
    }

    if (
      email === normalizeEmail(currentUser?.email)
    ) {
      setError("You cannot start a conversation with yourself.");
      return;
    }

    setCreatingChat(true);
    setError("");

    try {
      const conversation = await createConversation(email);

      await refreshConversations();

      setShowNewChat(false);
      setNewChatEmail("");

      if (conversation) {
        await selectConversation(conversation);
      }
    } catch (err) {
      setError(
        getSafeError(err, "Unable to create conversation.")
      );
    } finally {
      setCreatingChat(false);
    }
  };

  /* =====================================================
     GROUP CHAT
  ===================================================== */

  const handleGroupCreated = async (conversation) => {
    setShowGroupModal(false);
    setGroupModalConversation(null);

    await refreshConversations();

    if (conversation) {
      await selectConversation(conversation);
    }
  };

  const handleGroupMembersAdded = async (
    updatedConversation
  ) => {
    setShowGroupModal(false);
    setGroupModalConversation(null);

    await refreshConversations();

    if (updatedConversation) {
      await selectConversation(updatedConversation);
    } else if (selectedId) {
      const latest = await getMyConversations();

      const updated = latest.find(
        (item) => getConversationId(item) === selectedId
      );

      if (updated) {
        setSelectedChat(updated);
        selectedChatRef.current = updated;
      }
    }
  };

  const openNewGroup = () => {
    setGroupModalConversation(null);
    setShowGroupModal(true);
  };

  const openAddGroupMembers = () => {
  if (!selectedChat || !selectedIsGroup || !selectedIsAdmin) return;

  setShowGroupInfo(false);
  setGroupModalConversation(selectedChat);
  setShowGroupModal(true);
};
const handleGroupChanged = async () => {
  const previousId = selectedId;
  const latest = await getMyConversations();

  setConversations(sortConversations(latest || []));

  const updated = latest?.find(
    (item) => getConversationId(item) === previousId
  );

  if (updated) {
    setSelectedChat(updated);
    selectedChatRef.current = updated;
  } else {
    setSelectedChat(null);
    selectedChatRef.current = null;
    setMessages([]);
  }
};
const handleGroupRemoved = async () => {
  setShowGroupInfo(false);
  setShowGroupModal(false);
  setGroupModalConversation(null);

  const latest = await getMyConversations();

  setConversations(sortConversations(latest || []));

  const stillExists = latest?.find(
    (item) => getConversationId(item) === selectedId
  );

  if (stillExists) {
    setSelectedChat(stillExists);
    selectedChatRef.current = stillExists;
  } else {
    setSelectedChat(null);
    selectedChatRef.current = null;
    setMessages([]);
  }
};

  /* =====================================================
     ATTACHMENT SELECTION
  ===================================================== */

  const handleAttachmentSelect = (event) => {
    const file = event.target.files?.[0];

    event.target.value = "";

    if (!file || !selectedChat) return;

    if (file.size > MAX_FILE_SIZE) {
      setError("Files must be smaller than 25 MB.");
      return;
    }

    if (file.size === 0) {
      setError("This file is empty.");
      return;
    }

    setError("");

    setPendingAttachment((previous) => {
      if (previous?.previewUrl) {
        URL.revokeObjectURL(previous.previewUrl);
      }

      return {
        file,
        previewUrl: URL.createObjectURL(file),
      };
    });
  };

  const cancelPendingAttachment = () => {
    setPendingAttachment((previous) => {
      if (previous?.previewUrl) {
        URL.revokeObjectURL(previous.previewUrl);
      }

      return null;
    });

    setAttachmentCaption("");
  };

  /* =====================================================
     SEND ENCRYPTED ATTACHMENT WITH CAPTION / REPLY
  ===================================================== */

  const sendPendingAttachment = async () => {
    if (
      !pendingAttachment?.file ||
      !selectedChat ||
      uploading
    ) {
      return;
    }

      if (!checkContactTrustBeforeSend()) {
      return;
    }

    setUploading(true);
    setError("");

    try {
      const result = await sendAttachmentMessage({
        file: pendingAttachment.file,
        conversation: selectedChat,
        currentUserId,
        caption: attachmentCaption,
        replyTo: replyingTo
          ? getReplyReference(replyingTo)
          : null,
      });

      if (getId(result?.message)) {
        try {
          const plaintext = await decryptStoredMessage(
            result.message
          );

          setMessages((previous) =>
            upsertMessage(
              previous,
              normalizeMessage(result.message, plaintext)
            )
          );
        } catch {
          await loadMessages(selectedId);
        }
      } else {
        await loadMessages(selectedId);
      }

      cancelPendingAttachment();
      setReplyingTo(null);

      shouldAutoScrollRef.current = true;
      scrollToBottom(true);

      refreshConversations();
    } catch (err) {
      setError(
        getSafeError(err, "Unable to upload attachment.")
      );
    } finally {
      setUploading(false);
    }
  };

  /* =====================================================
     OPEN / DOWNLOAD ENCRYPTED ATTACHMENT
  ===================================================== */

  const handleOpenAttachment = async (attachment) => {
    if (!attachment?.attachmentId) {
      setError("Attachment is unavailable.");
      return;
    }

    const category = getMediaCategory(attachment.type);

    if (category === "document") {
      setError(
        "This document can be downloaded using the download button."
      );
      return;
    }

    setPreviewLoadingId(attachment.attachmentId);
    setError("");

    try {
      const result =
        await downloadAndDecryptAttachment(attachment);

      if (!result?.objectURL) {
        throw new Error(
          "Unable to prepare the media preview."
        );
      }

      const actualType =
        result.metadata?.type ||
        result.metadata?.mimeType ||
        attachment.type ||
        "";

      setAttachmentPreview({
        url: result.objectURL,
        type: actualType,
        name:
          result.metadata?.name ||
          attachment.name ||
          "Attachment",
        category: getMediaCategory(actualType),
      });
    } catch (err) {
      setError(
        getSafeError(err, "Unable to open attachment.")
      );
    } finally {
      setPreviewLoadingId(null);
    }
  };

  const handleDownloadAttachment = async (attachment) => {
    try {
      await saveAttachmentMessage(attachment);
    } catch (err) {
      setError(
        getSafeError(err, "Unable to download attachment.")
      );
    }
  };
    /* =====================================================
     AUDIO / VIDEO RECORDING
  ===================================================== */

  const startRecording = async (kind) => {
  if (!selectedChat || isRecording || uploading || sending) return;

  if (kind !== "audio" && kind !== "video") return;

  setRecordingError("");
  setError("");

  recordingCancelledRef.current = false;
  recordingChunksRef.current = [];

  try {
    if (!navigator.mediaDevices?.getUserMedia) {
      throw new Error(
        "Recording requires HTTPS or localhost."
      );
    }

    if (typeof MediaRecorder === "undefined") {
      throw new Error(
        "Your browser does not support recording."
      );
    }

    const stream = await navigator.mediaDevices.getUserMedia({
      audio: true,
      video: kind === "video"
        ? { facingMode: "user" }
        : false,
    });

    recordingStreamRef.current = stream;
    if (kind === "video") {
  setCameraStream(stream);
  setShowCameraPreview(true);
}

    const mimeType = getRecordingMimeType(kind);

    const recorder = mimeType
      ? new MediaRecorder(stream, { mimeType })
      : new MediaRecorder(stream);

    mediaRecorderRef.current = recorder;

    recorder.ondataavailable = (event) => {
      if (event.data && event.data.size > 0) {
        recordingChunksRef.current.push(event.data);
      }
    };

    recorder.onerror = () => {
      recordingCancelledRef.current = true;

      setRecordingError(
        "Recording failed. Please try again."
      );

      stopRecordingTracks();
    };

    recorder.onstop = () => {
      const wasCancelled = recordingCancelledRef.current;
      const chunks = [...recordingChunksRef.current];

      const actualType = (
  recorder.mimeType ||
  (kind === "video" ? "video/webm" : "audio/webm")
)
  .split(";")[0]
  .trim()
  .toLowerCase();

      // Stop tracks and reset recording state.
      stopRecordingTracks();

      if (wasCancelled) {
        recordingChunksRef.current = [];
        return;
      }

      const blob = new Blob(chunks, {
        type: actualType,
      });

      recordingChunksRef.current = [];

      if (!blob.size) {
        setRecordingError(
          "The recording is empty. Please try again."
        );
        return;
      }

      if (blob.size > MAX_FILE_SIZE) {
        setRecordingError(
          "The recording exceeds the 25 MB attachment limit."
        );
        return;
      }

      const extension = actualType.includes("ogg")
        ? "ogg"
        : actualType.includes("mp4")
          ? "mp4"
          : "webm";

      const fileName =
        `${kind === "video" ? "SecureX-Video" : "SecureX-Voice"}-` +
        `${Date.now()}.${extension}`;

      const recordedFile = new File(
        [blob],
        fileName,
        { type: actualType }
      );

      setPendingAttachment((previous) => {
        if (previous?.previewUrl) {
          URL.revokeObjectURL(previous.previewUrl);
        }

        return {
          file: recordedFile,
          previewUrl: URL.createObjectURL(recordedFile),
        };
      });

      setRecordingError("");
    };

    recorder.start(1000);

    setRecordingType(kind);
    setIsRecording(true);
    setRecordingSeconds(0);

    recordingTimerRef.current = setInterval(() => {
      setRecordingSeconds((previous) => previous + 1);
    }, 1000);

  } catch (err) {
    recordingCancelledRef.current = true;

    stopRecordingTracks();

    setRecordingError(
      getSafeError(
        err,
        "Unable to access your microphone or camera."
      )
    );
  }
};
/* =====================================================
   STOP RECORDING
===================================================== */

const stopRecording = () => {
  const recorder = mediaRecorderRef.current;

  if (!recorder || recorder.state === "inactive") {
    return;
  }

  recordingCancelledRef.current = false;

  try {
    recorder.stop();
  } catch (error) {
    console.error("SecureX stop recording error:", error);
    setRecordingError("Unable to stop recording.");
    stopRecordingTracks();
  }
};

/* =====================================================
   CANCEL RECORDING
===================================================== */

const cancelRecording = () => {
  const recorder = mediaRecorderRef.current;

  recordingCancelledRef.current = true;

  if (recorder && recorder.state !== "inactive") {
    try {
      recorder.stop();
    } catch (error) {
      console.error("SecureX cancel recording error:", error);
      stopRecordingTracks();
    }
  } else {
    stopRecordingTracks();
  }

  setRecordingError("");
};

     // Stop the active camera stream.
  const stopCameraStream = () => {
    if (cameraStreamRef.current) {
      cameraStreamRef.current.getTracks().forEach((track) => track.stop());
      cameraStreamRef.current = null;
    }

    if (cameraVideoRef.current) {
      cameraVideoRef.current.srcObject = null;
    }

    setCameraStream(null);
  };

  // Open live camera preview.
  const openCameraPreview = async (facingMode = cameraFacingMode) => {
    if (!selectedChat || uploading || isRecording || pendingAttachment) {
      return;
    }

    setShowCameraMenu(false);
    setRecordingError("");
    setError("");

    try {
      if (!navigator.mediaDevices?.getUserMedia) {
        throw new Error("Camera access requires HTTPS or localhost.");
      }

      stopCameraStream();

      const stream = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: { facingMode: { ideal: facingMode } },
      });

      cameraStreamRef.current = stream;
      setCameraStream(stream);
      setCameraFacingMode(facingMode);
      setShowCameraPreview(true);
    } catch (err) {
      setRecordingError(
        getSafeError(err, "Unable to access the camera.")
      );
    }
  };

  // Attach the camera stream to the preview video.
  useEffect(() => {
    if (!showCameraPreview || !cameraStream || !cameraVideoRef.current) {
      return;
    }

    cameraVideoRef.current.srcObject = cameraStream;

    cameraVideoRef.current.play().catch(() => {
      setRecordingError("Unable to start camera preview.");
    });
  }, [cameraStream, showCameraPreview]);

  // Switch between front and rear cameras.
  const switchCamera = () => {
    const nextMode =
      cameraFacingMode === "user" ? "environment" : "user";

    openCameraPreview(nextMode);
  };

  // Capture a photo from the live preview.
  const captureCameraPhoto = async () => {
    const video = cameraVideoRef.current;

    if (!video || !video.videoWidth || !video.videoHeight) {
      setRecordingError("Camera is not ready. Please try again.");
      return;
    }

    try {
      const canvas = document.createElement("canvas");
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;

      const context = canvas.getContext("2d");

      if (!context) {
        throw new Error("Unable to capture photo.");
      }

      context.drawImage(video, 0, 0, canvas.width, canvas.height);

      const blob = await new Promise((resolve, reject) => {
        canvas.toBlob(
          (result) => {
            if (result) resolve(result);
            else reject(new Error("Photo capture failed."));
          },
          "image/jpeg",
          0.92
        );
      });

      if (blob.size > MAX_FILE_SIZE) {
        throw new Error("Photo exceeds the 25 MB limit.");
      }

      const photoFile = new File(
        [blob],
        `SecureX-Photo-${Date.now()}.jpg`,
        { type: "image/jpeg" }
      );

      setCapturedPhoto({
        file: photoFile,
        previewUrl: URL.createObjectURL(photoFile),
      });

      stopCameraStream();
    } catch (err) {
      setRecordingError(
        getSafeError(err, "Unable to capture the photo.")
      );
    }
  };

  // Retake the captured photo.
  const retakePhoto = () => {
    if (capturedPhoto?.previewUrl) {
      URL.revokeObjectURL(capturedPhoto.previewUrl);
    }

    setCapturedPhoto(null);
    openCameraPreview(cameraFacingMode);
  };

  // Cancel and close camera preview.
  const closeCameraPreview = () => {
    stopCameraStream();

    if (capturedPhoto?.previewUrl) {
      URL.revokeObjectURL(capturedPhoto.previewUrl);
    }

    setCapturedPhoto(null);
    setShowCameraPreview(false);
  };

  // Send the captured photo into the existing encrypted attachment flow.
  const useCapturedPhoto = () => {
    if (!capturedPhoto?.file) return;

    stopCameraStream();
    setShowCameraPreview(false);

    setPendingAttachment((previous) => {
      if (previous?.previewUrl) {
        URL.revokeObjectURL(previous.previewUrl);
      }

      return {
        file: capturedPhoto.file,
        previewUrl: capturedPhoto.previewUrl,
      };
    });

    setCapturedPhoto(null);
    setAttachmentCaption("");
  };

  /* =====================================================
     REPLY TO MESSAGE
  ===================================================== */

  const handleReply = (message) => {
    setReplyingTo(message);
    setActiveMenuId(null);
    setEditingMessageId(null);

    messageInputRef.current?.focus();
  };

  const cancelReply = () => {
    setReplyingTo(null);
  };

  /* =====================================================
     MESSAGE ACTIONS
  ===================================================== */

  const handleCopyMessage = async (message) => {
    try {
      const attachment = getAttachmentInfo(message.plaintext);

      const reply = getReplyInfo(message.plaintext);

      const content = attachment
        ? attachment.caption || attachment.name
        : reply?.text || message.plaintext;

      await navigator.clipboard.writeText(
        toDisplayText(content)
      );

      setActiveMenuId(null);
    } catch {
      setError("Unable to copy message.");
    }
  };

  const handleStartEdit = (message) => {
    setEditingMessageId(getId(message));
    setEditingText(getMessageText(message));
    setActiveMenuId(null);
  };

  const handleSaveEdit = async (message) => {
    const text = editingText.trim();

    if (!text) {
      setError("Message cannot be empty.");
      return;
    }

        if (!checkContactTrustBeforeSend()) {
      return;
    }

    setSavingEdit(true);
    setError("");

    try {
      const clientMessageId = createClientMessageId();

      let encryptedPayload;

      if (selectedIsGroup) {
        encryptedPayload = await encryptMessageForGroup(
          text,
          getParticipants(selectedChat),
          clientMessageId,
          selectedId
        );
      } else {
        const recipient = getOtherParticipant(
          selectedChat,
          currentUserId
        );

        encryptedPayload = await encryptMessageForRecipient(
          text,
          getId(recipient),
          clientMessageId
        );
      }

      const response = await fetch(
        `${API_URL}/messages/${getId(message)}`,
        {
          method: "PATCH",
          headers: getAuthHeaders(),
          body: JSON.stringify(encryptedPayload),
        }
      );

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(
          toDisplayText(data.message) || "Unable to edit message."
        );
      }

      const updatedMessage =
        data.message || data.data || message;

      setMessages((previous) =>
        previous.map((item) =>
          getId(item) === getId(message)
            ? normalizeMessage(updatedMessage, text)
            : item
        )
      );

      setEditingMessageId(null);
      setEditingText("");
      setActiveMenuId(null);
    } catch (err) {
      setError(
        getSafeError(err, "Unable to edit message.")
      );
    } finally {
      setSavingEdit(false);
    }
  };

  const handleDeleteMessage = async (
    message,
    deleteForEveryone
  ) => {
    const messageId = getId(message);

    if (!messageId) return;

    const endpoint = deleteForEveryone
      ? `${API_URL}/messages/${messageId}/everyone`
      : `${API_URL}/messages/${messageId}/me`;

    if (
      deleteForEveryone &&
      !window.confirm("Delete this message for everyone?")
    ) {
      return;
    }

    try {
      const response = await fetch(endpoint, {
        method: "DELETE",
        headers: getAuthHeaders(),
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(
          toDisplayText(data.message) || "Unable to delete message."
        );
      }

      setMessages((previous) =>
        previous.filter(
          (item) => getId(item) !== messageId
        )
      );

      setActiveMenuId(null);

      if (editingMessageId === messageId) {
        setEditingMessageId(null);
        setEditingText("");
      }

      if (getId(replyingTo) === messageId) {
        setReplyingTo(null);
      }

      refreshConversations();
    } catch (err) {
      setError(
        getSafeError(err, "Unable to delete message.")
      );
    }
  };

  /* =====================================================
     FILTER CONVERSATIONS
  ===================================================== */

  const filteredConversations = conversations.filter(
    (conversation) => {
      const title = toDisplayText(
        getConversationTitle(conversation, currentUserId)
      );

      return title.toLowerCase().includes(
        search.toLowerCase()
      );
    }
  );

  /* =====================================================
     ATTACHMENT RENDERING
  ===================================================== */

  const renderAttachment = (attachment) => {
    if (!attachment?.attachmentId) {
      return <span>Attachment unavailable</span>;
    }

    const category = getMediaCategory(attachment.type);

    return (
      <div className={`sx-attachment sx-attachment-${category}`}>
        <div className="sx-attachment-icon">
          {getFileIcon(attachment.type)}
        </div>

        <div className="sx-attachment-details">
          <strong>
            {toDisplayText(attachment.name) || "Attachment"}
          </strong>

          <span>{formatFileSize(attachment.size)}</span>
        </div>

        <div className="sx-attachment-actions">
          <button
            type="button"
            title={
              category === "document"
                ? "Preview unavailable"
                : "Open preview"
            }
            aria-label="Open attachment preview"
            disabled={
              previewLoadingId === attachment.attachmentId ||
              category === "document"
            }
            onClick={() => handleOpenAttachment(attachment)}
          >
            {previewLoadingId === attachment.attachmentId
              ? "…"
              : "↗"}
          </button>

          <button
            type="button"
            title="Download attachment"
            aria-label="Download attachment"
            onClick={() => handleDownloadAttachment(attachment)}
          >
            ↓
          </button>
        </div>
      </div>
    );
  };

  /* =====================================================
     MESSAGE MENU
  ===================================================== */

  const renderMessageMenu = (message) => {
    const own = isOwnMessage(message, currentUserId);

    return (
      <div className="sx-message-menu">
        <button
          type="button"
          onClick={() => handleReply(message)}
        >
          ↩ Reply
        </button>

        <button
          type="button"
          onClick={() => handleCopyMessage(message)}
        >
          Copy
        </button>

        {own &&
          !selectedIsGroup &&
          !getAttachmentInfo(message.plaintext) && (
            <button
              type="button"
              onClick={() => handleStartEdit(message)}
            >
              Edit
            </button>
          )}

        <button
          type="button"
          onClick={() => handleDeleteMessage(message, false)}
        >
          Delete for me
        </button>

        {own && (
          <button
            type="button"
            className="sx-danger-option"
            onClick={() => handleDeleteMessage(message, true)}
          >
            Delete for everyone
          </button>
        )}
      </div>
    );
  };

  /* =====================================================
     MESSAGE RENDERING
  ===================================================== */

  const renderMessage = (message) => {
    const messageId = getId(message);
    if (message?.messageType === "system") {
  return (
    <div
      key={messageId}
      id={`sx-message-${messageId}`}
      className="sx-system-event"
      style={{
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        flexWrap: "wrap",
        gap: "8px",
        width: "fit-content",
        maxWidth: "85%",
        margin: "14px auto",
        padding: "9px 16px",
        border: "1px solid rgba(163, 75, 101, 0.35)",
        borderRadius: "12px",
        background: "rgba(133, 54, 78, 0.12)",
        color: "#d7a5b5",
        fontSize: "12px",
        textAlign: "center",
      }}
    >
      <span className="sx-system-event-text">
        {getSystemEventText(message)}
      </span>

      <span
        className="sx-system-event-time"
        style={{ color: "#85808a", fontSize: "10px" }}
      >
        {toDisplayText(formatTime(message.createdAt))}
      </span>
    </div>
  );
}

    const own = isOwnMessage(
      message,
      currentUserId
    );

    const attachment = getAttachmentInfo(
      message.plaintext
    );

    const replyEnvelope = getReplyInfo(
      message.plaintext
    );

    const senderName = getMessageSenderName(
      message,
      selectedChat,
      currentUser
    );

    const replyReference =
      attachment?.replyTo ||
      replyEnvelope?.replyTo;

    const contentText = attachment
      ? toDisplayText(attachment.caption)
      : replyEnvelope
        ? replyEnvelope.text
        : toDisplayText(message.plaintext);

    return (
      <div
        key={messageId}
        id={`sx-message-${messageId}`}
        className={`sx-message-row ${
          own ? "sx-own-row" : "sx-other-row"
        }`}
      >
        <div
          className={`sx-message ${
            own ? "sx-own" : "sx-other"
          }`}
        >
          <div className="sx-message-sender">
            {toDisplayText(senderName) ||
              (own ? "You" : "SecureX User")}
          </div>

          {replyReference?.messageId && (
            <button
              type="button"
              className="sx-reply-preview"
              title="Jump to original message"
              onClick={() =>
                jumpToMessage(replyReference.messageId)
              }
            >
              <span className="sx-reply-preview-bar" />

              <span className="sx-reply-preview-content">
                <strong>
                  {replyReference.senderName || "Message"}
                </strong>

                <small>
                  {replyReference.preview || "Original message"}
                </small>
              </span>
            </button>
          )}

          <div className="sx-message-top">
            <div className="sx-message-content">
              {message.decryptionFailed ? (
                <span className="sx-decrypt-error">
                  Unable to decrypt this message
                </span>
              ) : attachment ? (
                <>
                  {renderAttachment(attachment)}

                  {attachment.caption && (
                    <div className="sx-message-caption">
                      {renderMessageWithLinks(
                        attachment.caption
                      )}
                    </div>
                  )}
                </>
              ) : (
                <span className="sx-message-text">
                  {renderMessageWithLinks(contentText)}
                </span>
              )}
            </div>

            <button
              className="sx-message-options"
              type="button"
              title="Message options"
              aria-label="Message options"
              onClick={() =>
                setActiveMenuId((previous) =>
                  previous === messageId
                    ? null
                    : messageId
                )
              }
            >
              ⋮
            </button>

            {activeMenuId === messageId &&
              renderMessageMenu(message)}
          </div>

          <div className="sx-message-meta">
            <span>
              {toDisplayText(formatTime(message.createdAt))}
            </span>

            {own && (
              <span className="sx-message-tick">✓</span>
            )}
          </div>

          {editingMessageId === messageId && (
            <div className="sx-edit-box">
              <textarea
                value={editingText}
                onChange={(event) =>
                  setEditingText(event.target.value)
                }
                autoFocus
              />

              <div>
                <button
                  type="button"
                  onClick={() => {
                    setEditingMessageId(null);
                    setEditingText("");
                  }}
                >
                  Cancel
                </button>

                <button
                  type="button"
                  className="sx-primary-button"
                  disabled={savingEdit}
                  onClick={() => handleSaveEdit(message)}
                >
                  {savingEdit ? "Saving..." : "Save"}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  /* =====================================================
     CONVERSATION SIDEBAR ITEM
  ===================================================== */

  const renderConversation = (conversation) => {
    const conversationId = getId(conversation);

    const active = conversationId === selectedId;

    const title = toDisplayText(
      getConversationTitle(conversation, currentUserId)
    );

    const preview = toDisplayText(
      getSidebarPreview(conversation, currentUserId)
    );

    const unread =
      Number(getUnreadCount(conversation)) || 0;

    return (
      <button
        key={conversationId}
        type="button"
        className={`sx-conversation ${
          active ? "sx-active-conversation" : ""
        }`}
        onClick={() => selectConversation(conversation)}
      >
        <div className="sx-avatar">
          {isGroupConversation(conversation)
            ? <GroupIcon />
            : (title || "?").charAt(0).toUpperCase()}
        </div>

        <div className="sx-conversation-info">
          <div className="sx-conversation-heading">
            <strong>{title || "SecureX User"}</strong>

            <span>
              {toDisplayText(
                formatSidebarTime(
                  conversation.updatedAt ||
                  conversation.lastMessageAt ||
                  conversation.createdAt
                )
              )}
            </span>
          </div>

          <div className="sx-conversation-preview">
            <span>
              {preview || "Start a secure conversation"}
            </span>

            {unread > 0 && (
              <span className="sx-unread-badge">
                {unread > 99 ? "99+" : unread}
              </span>
            )}
          </div>
        </div>
      </button>
    );
  };

  /* =====================================================
     EMPTY STATE
  ===================================================== */

  const renderEmptyState = () => (
    <div className="sx-empty-state">
      <div className="sx-empty-logo">SX</div>

      <h2>Welcome to SecureX</h2>

      <p>
        Your conversations are protected with
        end-to-end encryption.
      </p>

      <span>
        Select a conversation or start a new one.
      </span>
    </div>
  );
    /* =====================================================
     SECURITY PANEL
  ===================================================== */
// Normalize SHA-256 fingerprints so colon-separated or spaced values compare safely.
const normalizeFingerprint = (value) =>
  String(value || "").replace(/[^a-fA-F0-9]/g, "").toLowerCase();
// Verify private contact's SHA-256 public-key fingerprint
const verifyContactFingerprint = () => {
  const actual = normalizeFingerprint(
    contactKeyInfo?.fingerprint
  );

  const supplied = normalizeFingerprint(sharedFingerprint);

  if (!contactKeyInfo || !otherParticipantId) {
    setKeyTrustStatus("ERROR");
    setError("Contact public key is unavailable.");
    return;
  }

  if (!/^[a-f0-9]{64}$/.test(actual)) {
    setKeyTrustStatus("INVALID");
    setError("The contact fingerprint is invalid.");
    return;
  }

  if (!/^[a-f0-9]{64}$/.test(supplied)) {
    setKeyTrustStatus("INVALID");
    setError("Enter the complete 64-character SHA-256 fingerprint.");
    return;
  }

  if (supplied !== actual) {
    setKeyTrustStatus("MISMATCH");
    setError("FINGERPRINT MISMATCH. Do not trust this public key.");
    return;
  }

  const storageKey =
    `securex_verified_key_${currentUserId}_${otherParticipantId}`;

  localStorage.setItem(
    storageKey,
    JSON.stringify({
      verified: true,
      fingerprint: actual,
      verifiedAt: new Date().toISOString(),
      verificationMethod: "user-confirmed-independent-comparison"
    })
  );

  setKeyTrustStatus("VERIFIED");
  setSharedFingerprint("");
  setError("");

  console.log("SECUREX: Contact fingerprint verified.");
};

// Verify a group member's fingerprint against a value received through
// an independent trusted channel (in person, verified call, or QR exchange).
const verifyGroupMemberFingerprint = (memberId, actualFingerprint) => {
  const suppliedFingerprint = normalizeFingerprint(
    groupFingerprints[memberId]
  );
  const actual = normalizeFingerprint(actualFingerprint);

  if (!/^[a-f0-9]{64}$/.test(actual)) {
    setError("The displayed public-key fingerprint is not a valid SHA-256 value.");
    return;
  }

  if (!/^[a-f0-9]{64}$/.test(suppliedFingerprint)) {
    setGroupKeyInfos((previous) =>
      previous.map((member) =>
        member.userId === memberId
          ? { ...member, status: "INVALID" }
          : member
      )
    );
    setError("Enter the complete 64-character SHA-256 fingerprint shared by this member.");
    return;
  }

  if (suppliedFingerprint !== actual) {
    setGroupKeyInfos((previous) =>
      previous.map((member) =>
        member.userId === memberId
          ? { ...member, status: "MISMATCH" }
          : member
      )
    );
    setError("FINGERPRINT MISMATCH. Do not trust this member's public key.");
    return;
  }

  const storageKey =
    `securex_verified_key_${currentUserId}_${memberId}`;

  localStorage.setItem(
    storageKey,
    JSON.stringify({
      verified: true,
      fingerprint: actual,
      verifiedAt: new Date().toISOString(),
      verificationMethod: "user-confirmed-independent-comparison"
    })
  );

  setGroupKeyInfos((previous) =>
    previous.map((member) =>
      member.userId === memberId
        ? { ...member, status: "VERIFIED" }
        : member
    )
  );

  setGroupFingerprints((previous) => ({
    ...previous,
    [memberId]: ""
  }));
  setError("");
};
const renderSecurityPanel = () => (
  <aside className="sx-security-panel">
<div className="sx-security-heading">
  <h3>
    <i className="bi bi-shield-lock-fill"></i>
    Security Center
  </h3>

  <button
    type="button"
    aria-label="Close security panel"
    onClick={() => setSecurityOpen(false)}
  >
    ×
  </button>
</div>

    <div className="sx-security-status">
  <div className="sx-security-status-icon">
    <i className="bi bi-shield-check"></i>
  </div>

  <div>
    <strong>Secure Session</strong>
    <small>
      Encryption session active
    </small>
  </div>

  <span className="sx-security-indicator" />
</div>
    {[
      ["ENCRYPTION", "AES-256-GCM",
        "Messages are encrypted before being sent."],

      ["KEY EXCHANGE", "RSA-OAEP-SHA256",
        "Encryption keys are wrapped for recipients."],

      ["MESSAGE STORAGE", "Encrypted payloads",
        "The server receives encrypted message content."],

      ["CONNECTION", socketConnected ? "Connected" : "Connecting",
        "SecureX realtime connection status."]
    ].map(([label, title, description]) => (
      <div className="sx-security-card" key={label}>
        <span>{label}</span>
        <strong>{title}</strong>
        <small>{description}</small>
      </div>
    ))}

    <div className="sx-security-card">

      <span>CONTACT KEY VERIFICATION</span>

      {selectedIsGroup ? (
  <div>
    <strong>GROUP MEMBER VERIFICATION</strong>

    {groupKeyLoading ? (
      <p>Retrieving group member public keys...</p>
    ) : groupKeyInfos.length === 0 ? (
      <p>No other group members found.</p>
    ) : (
      groupKeyInfos.map((member) => (
        <div
          key={member.userId}
          className="sx-security-card"
          style={{ marginTop: "12px" }}
        >
          <strong>{member.name}</strong>

          {member.status === "ERROR" ? (
            <p style={{ color: "#ff4444" }}>
              Unable to retrieve this member's public key.
            </p>
          ) : (
            <>
              <small>SHA-256 Safety Number</small>

              <p className="sx-safety-fingerprint">
                {member.fingerprint}
              </p>

              <strong
                style={{
                  color:
                    member.status === "VERIFIED"
                      ? "#00e676"
                      : member.status === "CHANGED" ||
                        member.status === "MISMATCH"
                      ? "#ff4444"
                      : "#ffc107"
                }}
              >
                {member.status === "VERIFIED"
                  ? "✓ VERIFIED"
                  : member.status === "CHANGED"
                  ? "⚠ PUBLIC KEY CHANGED"
                  : member.status === "MISMATCH"
                  ? "✕ FINGERPRINT MISMATCH"
                  : member.status === "INVALID"
                  ? "INVALID FINGERPRINT"
                  : "NOT VERIFIED"}
              </strong>

              <textarea
                value={groupFingerprints[member.userId] || ""}
                onChange={(event) =>
                  setGroupFingerprints((previous) => ({
                    ...previous,
                    [member.userId]: event.target.value
                  }))
                }
                placeholder="Paste fingerprint shared by this member"
                rows={3}
                className="sx-fingerprint-input"
              />

              <div className="sx-verification-actions">
                <button
                  type="button"
                  className="sx-verify-button"
                  disabled={!(groupFingerprints[member.userId] || "").trim()}
                  onClick={() =>
                    verifyGroupMemberFingerprint(
                      member.userId,
                      member.fingerprint
                    )
                  }
                >
                  Verify Member
                </button>

                <button
                  type="button"
                  className="sx-reset-verification-button"
                  onClick={() => {
                    localStorage.removeItem(
                      `securex_verified_key_${currentUserId}_${member.userId}`
                    );

                    setGroupFingerprints((previous) => ({
                      ...previous,
                      [member.userId]: ""
                    }));

                    setGroupKeyInfos((previous) =>
                      previous.map((item) =>
                        item.userId === member.userId
                          ? { ...item, status: "UNVERIFIED" }
                          : item
                      )
                    );
                  }}
                >
                  Reset Verification
                </button>
              </div>
            </>
          )}
        </div>
      ))
    )}
  </div>
) : !otherParticipantId ? (
        <p>Select a private conversation.</p>
      ) : keyTrustStatus === "LOADING" ? (
        <p>Retrieving contact public key...</p>
      ) : keyTrustStatus === "ERROR" ? (
        <p>Unable to retrieve contact public key.</p>
      ) : contactKeyInfo ? (

        <>
          <strong>
            {contactKeyInfo.name || "Contact"}
          </strong>

          <small>SHA-256 Safety Number</small>

          <p className="sx-safety-fingerprint">
            {contactKeyInfo.fingerprint}
          </p>

          {keyTrustStatus === "VERIFIED" && (
            <strong style={{ color: "#00e676" }}>
              ✓ FINGERPRINT VERIFIED
            </strong>
          )}

          {keyTrustStatus === "UNVERIFIED" && (
            <strong style={{ color: "#ffc107" }}>
              ⚠ NOT VERIFIED
            </strong>
          )}

          {keyTrustStatus === "CHANGED" && (
            <strong style={{ color: "#ff4444" }}>
              ⚠ PUBLIC KEY CHANGED — VERIFY AGAIN
            </strong>
          )}

          {keyTrustStatus === "MISMATCH" && (
            <strong style={{ color: "#ff4444" }}>
              ✕ FINGERPRINT MISMATCH
            </strong>
          )}

          {keyTrustStatus === "INVALID" && (
            <strong style={{ color: "#ffc107" }}>
              Invalid fingerprint format.
            </strong>
          )}

          <p>
            Compare this fingerprint with your contact
            through a separate trusted channel.
          </p>

          <textarea
            value={sharedFingerprint}
            onChange={(event) => {
              setSharedFingerprint(event.target.value);

              if (
                keyTrustStatus === "MISMATCH" ||
                keyTrustStatus === "INVALID"
              ) {
                setKeyTrustStatus("UNVERIFIED");
              }
            }}
            placeholder="Paste the fingerprint shared by your contact"
            rows={3}
            className="sx-fingerprint-input"
          />

          <button
            type="button"
            className="sx-primary-button sx-verify-button"
            disabled={!sharedFingerprint.trim()}
            onClick={verifyContactFingerprint}
          >
            Verify Safety Number
          </button>

          <button
            type="button"
            className="sx-reset-verification-button"
            onClick={() => {
              const storageKey =
                `securex_verified_key_${currentUserId}_${otherParticipantId}`;

              localStorage.removeItem(storageKey);
              setKeyTrustStatus("UNVERIFIED");
            }}
          >
            Reset Verification
          </button>
        </>

      ) : (
        <p>No contact key available.</p>
      )}

    </div>

  </aside>
);

  /* =====================================================
      NEW PRIVATE CHAT MODAL
  ===================================================== */

  const renderNewChatModal = () => {
    if (!showNewChat) return null;

    return (
      <div
        className="sx-modal-backdrop"
        onMouseDown={(event) => {
          if (event.target === event.currentTarget) {
            setShowNewChat(false);
          }
        }}
      >
        <form
          className="sx-modal"
          onSubmit={handleCreatePrivateChat}
        >
          <div className="sx-modal-heading">
            <div>
              <h2>New conversation</h2>
              <p>Start an encrypted private chat.</p>
            </div>

            <button
              type="button"
              onClick={() => setShowNewChat(false)}
            >
              ×
            </button>
          </div>

          <label>Recipient Gmail address</label>

          <input
            type="email"
            placeholder="name@gmail.com"
            value={newChatEmail}
            onChange={(event) =>
              setNewChatEmail(event.target.value)
            }
            required
          />

          <button
            type="submit"
            className="sx-primary-button sx-modal-submit"
            disabled={creatingChat}
          >
            {creatingChat ? "Starting..." : "Start conversation"}
          </button>
        </form>
      </div>
    );
  };
// Check contact verification before sending messages
// Check contact verification before sending messages
const checkContactTrustBeforeSend = () => {

  // GROUP CHAT VERIFICATION
  if (selectedIsGroup) {

    if (groupKeyLoading) {
      setError("Group member keys are still being checked. Please wait.");
      return false;
    }

    if (!groupKeyInfos.length) {
      setError("Unable to verify group members. Message sending blocked.");
      return false;
    }

    const blockedMembers = groupKeyInfos.filter(
      member =>
        member.status === "CHANGED" ||
        member.status === "MISMATCH" ||
        member.status === "ERROR"
    );

    if (blockedMembers.length > 0) {
      setError(
        `SECURITY BLOCK: Public key verification failed for: ${
          blockedMembers.map(member => member.name).join(", ")
        }. Resolve these issues before sending.`
      );
      return false;
    }

    const unverifiedMembers = groupKeyInfos.filter(
      member => member.status !== "VERIFIED"
    );

    if (unverifiedMembers.length > 0) {

      const fingerprintSignature = unverifiedMembers
        .map(member => {
          const fingerprint =
            member.fingerprint ||
            member.publicKeyFingerprint ||
            member.publicKey;

          return `${member._id || member.id || member.name}:${fingerprint || ""}`;
        })
        .sort()
        .join("||");

      const canRemember = unverifiedMembers.every(member =>
        Boolean(
          member.fingerprint ||
          member.publicKeyFingerprint ||
          member.publicKey
        )
      );

      const acknowledgementKey =
        `securex_group_fingerprint_ack_${fingerprintSignature}`;

      if (
        canRemember &&
        localStorage.getItem(acknowledgementKey) === "true"
      ) {
        return true;
      }

      const confirmed = window.confirm(
        `SECURITY WARNING: These group members have unverified fingerprints:\n\n${
          unverifiedMembers.map(member => member.name).join(", ")
        }\n\nTheir identities have not been independently verified. Send anyway?`
      );

      if (!confirmed) {
        return false;
      }

      if (canRemember) {
        localStorage.setItem(acknowledgementKey, "true");
      }

      return true;
    }

    return true;
  }

  // PRIVATE CHAT VERIFICATION
  if (!otherParticipantId) {
    setError("Unable to identify the recipient.");
    return false;
  }

  if (
    keyTrustStatus === "CHANGED" ||
    keyTrustStatus === "MISMATCH" ||
    keyTrustStatus === "ERROR"
  ) {
    setError(
      "SECURITY BLOCK: Contact public key verification failed. Verify the Safety Number before sending."
    );
    return false;
  }

  if (keyTrustStatus === "VERIFIED") {
    return true;
  }

  if (keyTrustStatus === "UNVERIFIED") {

    // Use the fingerprint already stored in your component.
    const contactFingerprint = contactKeyInfo?.fingerprint;

    if (!contactFingerprint) {
      return window.confirm(
        "WARNING: This contact's Safety Number has not been independently verified. Do you still want to send this encrypted message?"
      );
    }

    const acknowledgementKey =
      `securex_private_fingerprint_ack_${otherParticipantId}_${contactFingerprint}`;

    if (localStorage.getItem(acknowledgementKey) === "true") {
      return true;
    }

    const confirmed = window.confirm(
      "WARNING: This contact's Safety Number has not been independently verified. Do you still want to send this encrypted message?"
    );

    if (!confirmed) {
      return false;
    }

    localStorage.setItem(acknowledgementKey, "true");

    return true;
  }

  setError("Contact verification is unavailable. Please try again.");
  return false;
};
  /* =====================================================
     GROUP MODALS
  ===================================================== */

  const renderGroupModal = () => {
    if (!showGroupModal) return null;

    return (
      <GroupChatModal
        conversation={groupModalConversation}
        onClose={() => {
          setShowGroupModal(false);
          setGroupModalConversation(null);
        }}
        onCreated={handleGroupCreated}
        onAdded={handleGroupMembersAdded}
      />
    );
  };

  const renderGroupManagement = () => {
    if (!showGroupInfo || !selectedChat) return null;

    return (
      <GroupManagementPanel
        conversation={selectedChat}
        currentUserId={currentUserId}
        onClose={() => setShowGroupInfo(false)}
        onAddMembers={openAddGroupMembers}
        onChanged={handleGroupChanged}
        onRemoved={handleGroupRemoved}
      />
    );
  };

  /* =====================================================
     MEDIA VIEWER
  ===================================================== */

  const renderAttachmentPreview = () => {
    if (!attachmentPreview) return null;

    return (
      <div
        className="sx-preview-backdrop"
        role="dialog"
        aria-modal="true"
        aria-label="Media preview"
        onMouseDown={(event) => {
          if (event.target === event.currentTarget) {
            closeAttachmentPreview();
          }
        }}
      >
        <div className="sx-preview-window">
          <div className="sx-preview-header">
            <div className="sx-preview-title">
              <span className="sx-preview-file-icon">SX</span>

              <strong title={attachmentPreview.name}>
                {attachmentPreview.name}
              </strong>
            </div>

            <button
              type="button"
              aria-label="Close media preview"
              title="Close"
              onClick={closeAttachmentPreview}
            >
              ×
            </button>
          </div>

          <div className="sx-preview-content">
            {attachmentPreview.category === "image" && (
              <img
                src={attachmentPreview.url}
                alt={attachmentPreview.name}
              />
            )}

            {attachmentPreview.category === "video" && (
              <video
                src={attachmentPreview.url}
                controls
                autoPlay
                playsInline
              />
            )}

            {attachmentPreview.category === "audio" && (
              <div className="sx-audio-preview">
                <div className="sx-audio-preview-icon">♫</div>

                <strong>{attachmentPreview.name}</strong>

                <audio
                  src={attachmentPreview.url}
                  controls
                  autoPlay
                />
              </div>
            )}

            {attachmentPreview.category === "pdf" && (
              <iframe
                src={attachmentPreview.url}
                title={attachmentPreview.name}
              />
            )}
          </div>

          <div className="sx-preview-footer">
            <a
              href={attachmentPreview.url}
              download={attachmentPreview.name}
              className="sx-preview-download"
            >
              ↓ Download
            </a>

            <button
              type="button"
              onClick={closeAttachmentPreview}
            >
              Close preview
            </button>
          </div>
        </div>
      </div>
    );
  };

  /* =====================================================
     PENDING ATTACHMENT PREVIEW
  ===================================================== */

  const renderPendingAttachment = () => {
    if (!pendingAttachment?.file) return null;

    const file = pendingAttachment.file;
    const category = getMediaCategory(file.type);

    return (
      <div className="sx-pending-attachment">
        <div className="sx-pending-heading">
          <div>
            <strong>Attachment ready</strong>
            <small>
              {file.name} · {formatFileSize(file.size)}
            </small>
          </div>

          <button
            type="button"
            title="Remove attachment"
            aria-label="Remove attachment"
            onClick={cancelPendingAttachment}
          >
            ×
          </button>
        </div>

        {category === "image" && (
          <img
            className="sx-pending-image"
            src={pendingAttachment.previewUrl}
            alt="Attachment preview"
          />
        )}

        {category === "video" && (
          <video
            className="sx-pending-video"
            src={pendingAttachment.previewUrl}
            controls
            playsInline
          />
        )}

        {category === "audio" && (
          <audio
            className="sx-pending-audio"
            src={pendingAttachment.previewUrl}
            controls
          />
        )}

        <input
          className="sx-caption-input"
          type="text"
          maxLength={1000}
          placeholder="Add a caption (optional)..."
          value={attachmentCaption}
          onChange={(event) =>
            setAttachmentCaption(event.target.value)
          }
        />

        <button
          type="button"
          className="sx-primary-button sx-attachment-send"
          disabled={uploading}
          onClick={sendPendingAttachment}
        >
          {uploading ? "Encrypting and sending..." : "Send attachment"}
        </button>
      </div>
    );
  };

  /* =====================================================
     REPLY COMPOSER PREVIEW
  ===================================================== */

  const renderReplyComposer = () => {
    if (!replyingTo) return null;

    return (
      <div className="sx-reply-composer">
        <span className="sx-reply-composer-bar" />

        <div className="sx-reply-composer-content">
          <strong>
            Replying to{" "}
            {getMessageSenderName(
              replyingTo,
              selectedChat,
              currentUser
            )}
          </strong>

          <small>{getMessagePreview(replyingTo)}</small>
        </div>

        <button
          type="button"
          aria-label="Cancel reply"
          title="Cancel reply"
          onClick={cancelReply}
        >
          ×
        </button>
      </div>
    );
  };

  /* =====================================================
     RECORDING STATUS
  ===================================================== */

  const renderRecordingStatus = () => {
    if (!isRecording) return null;

    return (
      <div className="sx-recording-status">
        <span className="sx-recording-dot" />

        <strong>
          {recordingType === "video"
            ? "Recording video"
            : "Recording voice"}
        </strong>

        <span>{formatRecordingTime(recordingSeconds)}</span>

        <button
          type="button"
          onClick={cancelRecording}
        >
          Cancel
        </button>

        <button
          type="button"
          className="sx-stop-recording"
          onClick={stopRecording}
        >
          Stop
        </button>
      </div>
    );
  };

  /* =====================================================
     UI
  ===================================================== */

  return (
    <div className="sx-app">
      <style>{`
        * {
          box-sizing: border-box;
        }

        .sx-app {
          height: 100vh;
          width: 100%;
          overflow: hidden;
          display: flex;
          background: #080808;
          color: #f5f5f5;
          font-family: Inter, Arial, sans-serif;
        }

        .sx-sidebar {
          width: 340px;
          min-width: 300px;
          height: 100%;
          display: flex;
          flex-direction: column;
          background: #101010;
          border-right: 1px solid #292020;
          flex-shrink: 0;
        }

        .sx-sidebar-header {
          padding: 22px 18px;
          border-bottom: 1px solid #292020;
        }

        .sx-brand-row,
        .sx-sidebar-actions,
        .sx-chat-header-actions {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 9px;
        }

        .sx-brand {
          font-size: 25px;
          font-weight: 900;
          letter-spacing: 2px;
          color: #f4f4f4;
        }

        .sx-brand span {
          color: #f32643;
          text-shadow: 0 0 15px #f3264366;
        }

        .sx-user-label {
          margin-top: 9px;
          display: flex;
          flex-direction: column;
          gap: 4px;
          overflow-wrap: anywhere;
        }

        .sx-user-name {
          color: #eee;
          font-size: 13px;
          font-weight: 700;
        }

        .sx-user-email {
          color: #929292;
          font-size: 11px;
        }

        .sx-icon-button {
          border: 1px solid #382126;
          color: #ff5369;
          background: #1a1012;
          border-radius: 9px;
          padding: 8px 11px;
          cursor: pointer;
        }

        .sx-icon-button:hover {
          background: #38131c;
          border-color: #e52b48;
        }

        .sx-group-create-button {
          width: 39px;
          height: 37px;
          display: grid;
          place-items: center;
          padding: 0;
        }

        .sx-search {
          margin-top: 18px;
          width: 100%;
          padding: 11px 13px;
          background: #080808;
          border: 1px solid #302326;
          border-radius: 9px;
          outline: none;
          color: white;
        }

        .sx-search:focus,
        .sx-modal input:focus,
        .sx-caption-input:focus {
          border-color: #e52b48;
          box-shadow: 0 0 0 2px #e52b4820;
        }

        .sx-sidebar-section {
          padding: 15px 18px 9px;
          display: flex;
          justify-content: space-between;
          color: #999;
          font-size: 11px;
          font-weight: 700;
          letter-spacing: 1.5px;
        }

        .sx-conversation-list {
          flex: 1;
          overflow-y: auto;
          min-height: 0;
        }

        .sx-conversation {
          width: 100%;
          display: flex;
          align-items: center;
          gap: 12px;
          text-align: left;
          border: 0;
          border-bottom: 1px solid #1c1c1c;
          background: transparent;
          color: white;
          padding: 14px 16px;
          cursor: pointer;
        }

        .sx-conversation:hover {
          background: #191315;
        }

        .sx-active-conversation {
          background: #251216;
          border-left: 3px solid #ed2948;
        }

        .sx-avatar {
          width: 43px;
          height: 43px;
          flex-shrink: 0;
          display: grid;
          place-items: center;
          border-radius: 50%;
          background: linear-gradient(145deg, #3b111b, #160c0e);
          border: 1px solid #762437;
          color: #ff526b;
          font-size: 17px;
          font-weight: 800;
        }

        .sx-conversation-info {
          min-width: 0;
          flex: 1;
        }

        .sx-conversation-heading,
        .sx-conversation-preview {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 8px;
        }

        .sx-conversation-heading strong {
          font-size: 13px;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }

        .sx-conversation-heading > span {
          flex-shrink: 0;
          color: #777;
          font-size: 10px;
        }

        .sx-conversation-preview {
          margin-top: 7px;
          color: #888;
          font-size: 11px;
        }

        .sx-conversation-preview > span:first-child {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }

        .sx-unread-badge {
          flex-shrink: 0;
          min-width: 19px;
          height: 19px;
          padding: 0 5px;
          display: grid;
          place-items: center;
          border-radius: 20px;
          background: #ed2948;
          color: white;
          font-size: 10px;
          font-weight: 800;
        }

        .sx-sidebar-footer {
          padding: 12px;
          display: flex;
          align-items: center;
          gap: 10px;
          border-top: 1px solid #292020;
          background: #101010;
          flex-shrink: 0;
        }

        .sx-account-info {
          flex: 1;
          min-width: 0;
          display: flex;
          align-items: center;
          gap: 9px;
        }

        .sx-account-avatar {
          width: 37px;
          height: 37px;
          flex-shrink: 0;
          display: grid;
          place-items: center;
          border-radius: 50%;
          background: linear-gradient(145deg, #571525, #1a0b10);
          border: 1px solid #a52c45;
          color: #ff7187;
          font-size: 14px;
          font-weight: 900;
        }

        .sx-account-details {
          min-width: 0;
          flex: 1;
          display: flex;
          flex-direction: column;
          gap: 4px;
          overflow: hidden;
        }

        .sx-account-details strong,
        .sx-account-details small {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }

        .sx-account-details strong {
          font-size: 12px;
        }

        .sx-account-details small {
          color: #929292;
          font-size: 10px;
        }

        .sx-logout-button {
          flex-shrink: 0;
          padding: 9px 13px;
          border: 1px solid #692536;
          border-radius: 8px;
          color: #ff7187;
          background: #211015;
          cursor: pointer;
          font-size: 11px;
        }

        .sx-chat-area {
          flex: 1;
          min-width: 0;
          height: 100%;
          display: flex;
          flex-direction: column;
          position: relative;
          background:
            radial-gradient(ellipse at 50% 40%, #21101355, transparent 65%),
            #090909;
        }

        .sx-chat-header {
          min-height: 75px;
          flex-shrink: 0;
          padding: 0 22px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
          border-bottom: 1px solid #2b2022;
          background: #101010;
        }

        .sx-chat-person {
          display: flex;
          align-items: center;
          gap: 12px;
          min-width: 0;
        }

        .sx-chat-person-info {
          min-width: 0;
        }

        .sx-chat-person-info strong {
          display: block;
          font-size: 14px;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }

        .sx-chat-person-info small {
          display: block;
          margin-top: 5px;
          color: #8f8f8f;
          font-size: 11px;
        }

        .sx-chat-header-actions {
          flex-shrink: 0;
        }

        .sx-chat-header-actions button {
          border: 1px solid #392027;
          background: #1a1012;
          color: #ff5369;
          padding: 8px 12px;
          border-radius: 8px;
          cursor: pointer;
        }

        .sx-chat-header-actions button:hover {
          background: #38131c;
        }

        .sx-messages {
          flex: 1;
          min-height: 0;
          overflow-y: auto;
          padding: 24px clamp(15px, 5vw, 65px);
          display: flex;
          flex-direction: column;
          gap: 12px;
          overscroll-behavior: contain;
          scroll-behavior: smooth;
        }

        .sx-message-row {
          display: flex;
          justify-content: flex-start;
          width: 100%;
          scroll-margin: 100px;
        }

        .sx-own-row {
          justify-content: flex-end;
        }

        .sx-message {
          max-width: min(75%, 580px);
          min-width: 100px;
          position: relative;
          padding: 11px 13px 7px;
          border: 1px solid #332629;
          border-radius: 12px 12px 12px 3px;
          background: #171415;
          overflow-wrap: anywhere;
          animation: sx-message-appear .18s ease-out;
        }

        .sx-own {
          background: #35131c;
          border-color: #762437;
          border-radius: 12px 12px 3px 12px;
        }

        .sx-message-highlight .sx-message {
          border-color: #ff526b;
          box-shadow: 0 0 0 2px #ed294855, 0 0 25px #ed294866;
        }

        @keyframes sx-message-appear {
          from {
            opacity: 0;
            transform: translateY(5px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }

        .sx-message-sender {
          color: #ff6377;
          font-size: 11px;
          font-weight: 800;
          margin-bottom: 7px;
        }

        .sx-message-top {
          display: flex;
          align-items: flex-start;
          gap: 8px;
        }

        .sx-message-content {
          flex: 1;
          min-width: 0;
          font-size: 13px;
          line-height: 1.55;
          white-space: pre-wrap;
        }

        .sx-message-text {
          overflow-wrap: anywhere;
        }

        .sx-message-link {
          color: #ff7187;
          text-decoration: underline;
          text-decoration-color: #a92b43;
          overflow-wrap: anywhere;
        }

        .sx-message-options {
          opacity: .45;
          border: 0;
          background: transparent;
          color: white;
          cursor: pointer;
          font-size: 17px;
          line-height: 17px;
          padding: 0 2px;
          flex-shrink: 0;
        }

        .sx-message:hover .sx-message-options {
          opacity: 1;
        }

        .sx-message-meta {
          display: flex;
          justify-content: flex-end;
          gap: 5px;
          margin-top: 5px;
          color: #a28d91;
          font-size: 9px;
        }

        .sx-message-tick {
          color: #ff647a;
          font-weight: 900;
        }

        .sx-message-menu {
          position: absolute;
          top: 27px;
          right: 7px;
          z-index: 20;
          min-width: 165px;
          padding: 5px;
          background: #1b1718;
          border: 1px solid #63303b;
          border-radius: 9px;
          box-shadow: 0 10px 30px #000b;
        }

        .sx-message-menu button {
          width: 100%;
          padding: 9px 10px;
          border: 0;
          border-radius: 5px;
          background: transparent;
          color: #eee;
          text-align: left;
          cursor: pointer;
          font-size: 11px;
        }

        .sx-message-menu button:hover {
          background: #382027;
        }

        .sx-danger-option {
          color: #ff526b !important;
        }

        .sx-attachment {
          min-width: 230px;
          max-width: 100%;
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 9px;
          background: #09090955;
          border: 1px solid #57303a;
          border-radius: 8px;
        }

        .sx-attachment-icon {
          min-width: 35px;
          height: 35px;
          display: grid;
          place-items: center;
          border-radius: 7px;
          background: #441522;
          color: #ff6a80;
          font-size: 12px;
          font-weight: 900;
        }

        .sx-attachment-details {
          min-width: 0;
          flex: 1;
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .sx-attachment-details strong {
          overflow-wrap: anywhere;
          font-size: 11px;
        }

        .sx-attachment-details span {
          color: #aaa;
          font-size: 10px;
        }

        .sx-attachment-actions {
          display: flex;
          gap: 4px;
        }

        .sx-attachment-actions button {
          border: 0;
          background: transparent;
          color: #ff687d;
          cursor: pointer;
          font-size: 17px;
          padding: 5px;
        }

        .sx-attachment-actions button:disabled {
          opacity: .35;
          cursor: not-allowed;
        }

        .sx-message-caption {
          margin-top: 8px;
          font-size: 13px;
          line-height: 1.5;
        }

        .sx-reply-preview {
          width: 100%;
          display: flex;
          gap: 9px;
          text-align: left;
          padding: 8px;
          margin-bottom: 8px;
          border: 1px solid #713044;
          border-radius: 7px;
          background: #0d090a88;
          color: white;
          cursor: pointer;
        }

        .sx-reply-preview:hover {
          background: #30131b;
        }

        .sx-reply-preview-bar,
        .sx-reply-composer-bar {
          width: 3px;
          min-width: 3px;
          border-radius: 5px;
          background: #ff526b;
        }

        .sx-reply-preview-content,
        .sx-reply-composer-content {
          min-width: 0;
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .sx-reply-preview-content strong,
        .sx-reply-composer-content strong {
          color: #ff7589;
          font-size: 10px;
        }

        .sx-reply-preview-content small,
        .sx-reply-composer-content small {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          color: #c4b8ba;
          font-size: 10px;
        }

        .sx-decrypt-error {
          color: #ff6678;
          font-size: 12px;
        }

        .sx-edit-box {
          margin-top: 10px;
        }

        .sx-edit-box textarea {
          width: 100%;
          min-height: 65px;
          resize: vertical;
          background: #090909;
          border: 1px solid #743044;
          border-radius: 7px;
          color: white;
          padding: 9px;
        }

        .sx-edit-box > div {
          display: flex;
          justify-content: flex-end;
          gap: 7px;
          margin-top: 7px;
        }

        .sx-edit-box button {
          border: 1px solid #493039;
          border-radius: 6px;
          background: #171112;
          color: white;
          padding: 6px 10px;
          cursor: pointer;
        }

        .sx-composer-area {
          flex-shrink: 0;
          padding: 10px 22px 16px;
          background: #101010;
          border-top: 1px solid #2b2022;
        }

        .sx-composer {
          display: flex;
          align-items: flex-end;
          gap: 9px;
        }

        .sx-composer textarea {
          flex: 1;
          min-width: 0;
          min-height: 43px;
          max-height: 130px;
          resize: vertical;
          border: 1px solid #3b292e;
          border-radius: 10px;
          background: #080808;
          color: white;
          padding: 12px 14px;
          outline: none;
          font: inherit;
          font-size: 13px;
        }

        .sx-composer textarea:focus {
          border-color: #e52b48;
        }

        .sx-composer-button {
          width: 43px;
          height: 43px;
          flex-shrink: 0;
          border: 1px solid #7d2639;
          border-radius: 10px;
          background: #42121e;
          color: #ff647a;
          cursor: pointer;
          font-size: 19px;
        }

        .sx-composer-button:hover {
          background: #6a192b;
        }

        .sx-composer-button:disabled {
          opacity: .45;
          cursor: not-allowed;
        }

        .sx-typing {
          padding: 0 25px 8px;
          color: #ff7588;
          font-size: 11px;
          background: #101010;
        }

        .sx-reply-composer {
          display: flex;
          align-items: stretch;
          gap: 10px;
          margin-bottom: 10px;
          padding: 9px 11px;
          border: 1px solid #46222d;
          border-radius: 8px;
          background: #171112;
        }

        .sx-reply-composer-content {
          flex: 1;
        }

        .sx-reply-composer > button,
        .sx-pending-heading > button {
          border: 0;
          background: transparent;
          color: #ff7187;
          font-size: 21px;
          cursor: pointer;
        }

        .sx-pending-attachment {
          max-width: 520px;
          margin: 0 0 10px;
          padding: 11px;
          border: 1px solid #60303c;
          border-radius: 9px;
          background: #191214;
        }

        .sx-pending-heading {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 10px;
          margin-bottom: 9px;
        }

        .sx-pending-heading > div {
          min-width: 0;
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .sx-pending-heading strong {
          color: #ff7187;
          font-size: 12px;
        }

        .sx-pending-heading small {
          color: #aaa;
          font-size: 10px;
          overflow-wrap: anywhere;
        }

        .sx-pending-image,
        .sx-pending-video {
          display: block;
          max-width: 100%;
          max-height: 180px;
          margin: 8px 0;
          border-radius: 7px;
        }

        .sx-pending-audio {
          display: block;
          width: 100%;
          margin: 8px 0;
        }

        .sx-caption-input {
          width: 100%;
          padding: 10px;
          border: 1px solid #493039;
          border-radius: 7px;
          background: #080808;
          color: white;
          outline: none;
        }

        .sx-attachment-send {
          margin-top: 9px;
          width: 100%;
        }

        .sx-recording-status {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 10px 12px;
          margin-bottom: 10px;
          border: 1px solid #783044;
          border-radius: 8px;
          background: #271016;
          color: #ff7187;
          font-size: 11px;
        }

        .sx-recording-status > strong {
          flex: 1;
        }

        .sx-recording-status button {
          border: 1px solid #693044;
          border-radius: 6px;
          padding: 6px 9px;
          background: #160c0f;
          color: #ff9aaa;
          cursor: pointer;
        }

        .sx-recording-status .sx-stop-recording {
          background: #7a1c32;
          color: white;
        }

        .sx-recording-dot {
          width: 9px;
          height: 9px;
          border-radius: 50%;
          background: #ff314f;
          box-shadow: 0 0 10px #ff314f;
          animation: sx-recording-pulse 1s infinite;
        }

        @keyframes sx-recording-pulse {
          50% { opacity: .3; }
        }

        .sx-recording-error {
          color: #ff7187;
          font-size: 11px;
          padding: 5px 0;
        }

        .sx-empty-state {
          flex: 1;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          padding: 25px;
          text-align: center;
        }

        .sx-empty-logo {
          width: 75px;
          height: 75px;
          display: grid;
          place-items: center;
          border: 1px solid #9d2c43;
          border-radius: 22px;
          background: #281016;
          color: #ff526b;
          font-size: 27px;
          font-weight: 900;
          box-shadow: 0 0 35px #ed294822;
        }

        .sx-empty-state h2 {
          margin: 22px 0 7px;
          font-size: 23px;
        }

        .sx-empty-state p,
        .sx-empty-state span {
          color: #888;
          font-size: 12px;
          line-height: 1.7;
        }

        .sx-empty-state span {
          color: #ff6575;
        }

        .sx-security-panel {
          width: 270px;
          flex-shrink: 0;
          padding: 18px;
          overflow-y: auto;
          background: #101010;
          border-left: 1px solid #302124;
          position: relative;
          z-index: 35;
        }

        .sx-security-heading {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 20px;
        }

        .sx-security-heading h3 {
          margin: 0;
          font-size: 14px;
        }

        .sx-security-heading button {
          border: 0;
          background: transparent;
          color: #ff647a;
          font-size: 21px;
          cursor: pointer;
        }

        .sx-security-status {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 12px;
          border: 1px solid #25462f;
          border-radius: 9px;
          background: #102016;
        }

        .sx-security-indicator {
          width: 9px;
          height: 9px;
          border-radius: 50%;
          background: #4bd77b;
          box-shadow: 0 0 12px #4bd77b;
        }

        .sx-security-status strong,
        .sx-security-status small {
          display: block;
        }

        .sx-security-status strong {
          font-size: 11px;
        }

        .sx-security-status small {
          margin-top: 4px;
          color: #91a798;
          font-size: 9px;
        }

        .sx-security-card {
          margin-top: 12px;
          padding: 13px;
          border: 1px solid #33252a;
          border-radius: 9px;
          background: #171314;
        }

        .sx-security-card span,
        .sx-security-card strong,
        .sx-security-card small {
          display: block;
        }

        .sx-security-card span {
          color: #ff647a;
          font-size: 9px;
          letter-spacing: 1px;
        }

        .sx-security-card strong {
          margin-top: 8px;
          font-size: 11px;
        }

        .sx-security-card small {
          margin-top: 6px;
          color: #999;
          font-size: 10px;
          line-height: 1.5;
        }

        .sx-error {
          position: absolute;
          z-index: 50;
          left: 50%;
          bottom: 85px;
          transform: translateX(-50%);
          max-width: 90%;
          padding: 10px 16px;
          border: 1px solid #9e3044;
          border-radius: 8px;
          background: #35111b;
          color: #ff9aaa;
          font-size: 12px;
          box-shadow: 0 8px 25px #0009;
        }

        .sx-modal-backdrop {
          position: fixed;
          inset: 0;
          z-index: 100;
          display: grid;
          place-items: center;
          padding: 18px;
          background: #000b;
        }

        .sx-modal {
          width: min(420px, 100%);
          padding: 23px;
          border: 1px solid #733043;
          border-radius: 13px;
          background: #151112;
          box-shadow: 0 20px 70px #000c;
        }

        .sx-modal-heading {
          display: flex;
          align-items: flex-start;
          justify-content: space-between;
          margin-bottom: 22px;
        }

        .sx-modal-heading h2 {
          margin: 0;
          font-size: 19px;
        }

        .sx-modal-heading p {
          margin: 7px 0 0;
          color: #999;
          font-size: 11px;
        }

        .sx-modal-heading button {
          border: 0;
          background: transparent;
          color: #ff6379;
          font-size: 23px;
          cursor: pointer;
        }

        .sx-modal label {
          display: block;
          margin-bottom: 8px;
          color: #bbb;
          font-size: 11px;
        }

        .sx-modal input {
          width: 100%;
          padding: 12px;
          border: 1px solid #493039;
          border-radius: 8px;
          background: #080808;
          color: white;
          outline: none;
        }

        .sx-primary-button {
          border: 1px solid #a12d46 !important;
          background: #571525 !important;
          color: white !important;
          border-radius: 7px;
          padding: 9px 14px;
          cursor: pointer;
        }

        .sx-primary-button:hover {
          background: #762039 !important;
        }

        .sx-primary-button:disabled {
          opacity: .5;
          cursor: not-allowed;
        }

        .sx-modal-submit {
          width: 100%;
          margin-top: 18px;
          padding: 12px;
        }

        .sx-loading {
          flex: 1;
          display: grid;
          place-items: center;
          color: #ff647a;
          font-size: 13px;
        }

        .sx-mobile-back {
          display: none;
        }

        .sx-preview-backdrop {
          position: fixed;
          inset: 0;
          z-index: 200;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 20px;
          background: rgba(0, 0, 0, .9);
          backdrop-filter: blur(9px);
        }

        .sx-preview-window {
          width: min(1050px, 96vw);
          height: min(780px, 92vh);
          display: flex;
          flex-direction: column;
          overflow: hidden;
          background: #100d0e;
          border: 1px solid #873047;
          border-radius: 13px;
          box-shadow: 0 0 55px #ed294833;
        }

        .sx-preview-header {
          min-height: 58px;
          padding: 10px 17px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
          border-bottom: 1px solid #382027;
          background: #171112;
        }

        .sx-preview-title {
          min-width: 0;
          display: flex;
          align-items: center;
          gap: 11px;
        }

        .sx-preview-title strong {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          font-size: 13px;
        }

        .sx-preview-file-icon {
          width: 32px;
          height: 32px;
          flex-shrink: 0;
          display: grid;
          place-items: center;
          border: 1px solid #873047;
          border-radius: 8px;
          background: #35131c;
          color: #ff647a;
          font-size: 11px;
          font-weight: 900;
        }

        .sx-preview-header > button {
          width: 35px;
          height: 35px;
          border: 0;
          border-radius: 7px;
          background: transparent;
          color: #ff647a;
          font-size: 27px;
          cursor: pointer;
        }

        .sx-preview-content {
          flex: 1;
          min-height: 0;
          display: flex;
          align-items: center;
          justify-content: center;
          overflow: auto;
          padding: 15px;
          background: #050505;
        }

        .sx-preview-content img,
        .sx-preview-content video {
          max-width: 100%;
          max-height: 100%;
          object-fit: contain;
        }

        .sx-preview-content audio {
          width: min(500px, 100%);
        }

        .sx-preview-content iframe {
          width: 100%;
          height: 100%;
          border: 0;
          background: white;
        }

        .sx-audio-preview {
          width: min(520px, 100%);
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 20px;
          padding: 35px 20px;
          border: 1px solid #47212c;
          border-radius: 13px;
          background: #151012;
        }

        .sx-audio-preview-icon {
          width: 100px;
          height: 100px;
          display: grid;
          place-items: center;
          border: 1px solid #9e3048;
          border-radius: 50%;
          background: #35131c;
          color: #ff647a;
          font-size: 45px;
        }

        .sx-audio-preview audio {
          width: 100%;
        }

        .sx-preview-footer {
          min-height: 58px;
          display: flex;
          justify-content: flex-end;
          align-items: center;
          gap: 10px;
          padding: 10px 15px;
          border-top: 1px solid #382027;
          background: #171112;
        }

        .sx-preview-footer button,
        .sx-preview-download {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          padding: 9px 15px;
          border: 1px solid #873047;
          border-radius: 7px;
          background: #32121b;
          color: #ff7187;
          text-decoration: none;
          font-size: 12px;
          cursor: pointer;
        }

        .sx-conversation-list,
        .sx-messages,
        .sx-security-panel {
          scrollbar-width: thin;
          scrollbar-color: #a92742 #100b0d;
        }

        .sx-conversation-list::-webkit-scrollbar,
        .sx-messages::-webkit-scrollbar,
        .sx-security-panel::-webkit-scrollbar {
          width: 7px;
        }

        .sx-conversation-list::-webkit-scrollbar-thumb,
        .sx-messages::-webkit-scrollbar-thumb,
        .sx-security-panel::-webkit-scrollbar-thumb {
          background: linear-gradient(180deg, #f13b59, #751629);
          border-radius: 10px;
        }

        @media (max-width: 1100px) {
          .sx-sidebar {
            width: 300px;
            min-width: 260px;
          }

          .sx-security-panel {
            position: absolute;
            z-index: 30;
            right: 0;
            top: 75px;
            bottom: 0;
            width: 270px;
            box-shadow: -10px 0 35px #0009;
          }
        }

        @media (max-width: 650px) {
          .sx-app {
            position: relative;
          }

          .sx-sidebar {
            width: 100%;
            min-width: 0;
            position: absolute;
            inset: 0;
            z-index: 5;
          }

          .sx-sidebar.sx-sidebar-hidden {
            display: none;
          }

          .sx-chat-area {
            width: 100%;
          }

          .sx-mobile-back {
            display: inline-block;
            border: 0;
            background: transparent;
            color: #ff647a;
            font-size: 21px;
            cursor: pointer;
          }

          .sx-chat-header {
            padding: 0 12px;
            gap: 7px;
          }

          .sx-chat-header-actions {
            gap: 4px;
          }

          .sx-chat-header-actions button {
            padding: 7px 8px;
            font-size: 10px;
          }

          .sx-messages {
            padding: 16px 10px;
          }

          .sx-message {
            max-width: 88%;
          }

          .sx-composer-area {
            padding: 10px;
          }

          .sx-composer {
            gap: 6px;
          }

          .sx-composer textarea {
            font-size: 12px;
          }

          .sx-sidebar-header {
            padding: 18px 14px;
          }

          .sx-security-panel {
            width: min(290px, 85vw);
          }

          .sx-attachment {
            min-width: 0;
          }

          .sx-preview-backdrop {
            padding: 8px;
          }

          .sx-preview-window {
            width: 100%;
            height: 88vh;
          }
        }

        @media (max-width: 380px) {
          .sx-brand {
            font-size: 21px;
          }

          .sx-sidebar-actions {
            gap: 5px;
          }

          .sx-chat-header-actions button {
            padding: 6px;
          }

          .sx-composer-button {
            width: 38px;
            height: 40px;
          }

          .sx-sidebar-footer {
            gap: 6px;
            padding: 9px;
          }

          .sx-account-avatar {
            width: 33px;
            height: 33px;
          }

          .sx-account-details strong {
            font-size: 11px;
          }

          .sx-logout-button {
            padding: 8px 9px;
          }
        }

        @media (prefers-reduced-motion: reduce) {
          .sx-message {
            animation: none;
          }

          .sx-messages {
            scroll-behavior: auto;
          }
        }
        /* SecureX group fingerprint verification controls */
        .sx-verification-actions {
          display: flex;
          flex-wrap: wrap;
          gap: 9px;
          margin-top: 12px;
        }

        .sx-verification-actions button {
          appearance: none !important;
          -webkit-appearance: none !important;
          background-image: none !important;
          border-radius: 7px !important;
          padding: 10px 13px !important;
          font-size: 11px !important;
          font-weight: 700 !important;
          cursor: pointer;
          transition: background .18s ease, border-color .18s ease, box-shadow .18s ease;
        }

        .sx-verification-actions .sx-verify-button {
          color: #fff !important;
          background: #501522 !important;
          border: 1px solid #a34b65 !important;
        }

        .sx-verification-actions .sx-verify-button:hover:not(:disabled) {
          background: #85364e !important;
          box-shadow: 0 0 12px rgba(163, 75, 101, .3);
        }

        .sx-verification-actions .sx-reset-verification-button {
          color: #e4b7c2 !important;
          background: #111113 !important;
          border: 1px solid #63303e !important;
        }

        .sx-verification-actions .sx-reset-verification-button:hover {
          color: #fff !important;
          background: #291016 !important;
        }

        .sx-verification-actions button:disabled {
          opacity: .45;
          cursor: not-allowed;
        }
/* =====================================================
    SECUREX SECURITY PANEL — BLACK / CRIMSON UNIFIED THEME
  ===================================================== */
        .sx-security-panel {
          width: 310px;
          min-width: 290px;
          max-width: 340px;
          box-sizing: border-box;
          background: #050507;
          color: #d0cbd3;
          border-left: 1px solid #633044;
          font-family: Inter, sans-serif;
          font-size: 12px;
        }

        .sx-security-panel *,
        .sx-security-panel *::before,
        .sx-security-panel *::after {
          box-sizing: border-box;
        }

        .sx-security-panel .sx-security-heading h3 {
          color: #e2dce4;
          font-size: 14px;
          font-weight: 650;
          letter-spacing: .25px;
        }

        .sx-security-panel .sx-security-card {
          min-width: 0;
          padding: 13px;
          border: 1px solid #492332;
          border-radius: 10px;
          background: linear-gradient(145deg, #100b0f, #09080b);
          box-shadow: 0 5px 14px #0008, inset 0 1px 0 #ffffff08;
          overflow: hidden;
        }

        .sx-security-panel .sx-security-card p {
          margin: 8px 0;
          color: #aaa2ad;
          font-size: 11px;
          line-height: 1.55;
        }

        .sx-security-panel .sx-security-card strong {
          color: #e1dbe3;
          font-size: 11px;
          line-height: 1.45;
        }

        .sx-security-panel .sx-security-card small {
          color: #918894;
          font-size: 10px;
          line-height: 1.5;
        }

        .sx-security-panel .sx-safety-fingerprint {
          display: block;
          width: 100%;
          max-width: 100%;
          margin: 8px 0 12px;
          padding: 10px;
          border: 1px solid #542638;
          border-radius: 7px;
          background: #070609;
          color: #f0dce3;
          font-family: "IBM Plex Mono", "Courier New", monospace;
          font-size: 10px !important;
          font-weight: 500;
          line-height: 1.8;
          letter-spacing: .25px;
          overflow-wrap: anywhere;
          word-break: break-word;
          user-select: text;
        }

        .sx-security-panel .sx-fingerprint-input,
        .sx-security-panel textarea,
        .sx-security-panel input,
        .sx-security-panel select {
          display: block;
          width: 100%;
          min-width: 0;
          min-height: 76px;
          margin: 10px 0;
          padding: 10px 11px;
          border: 1px solid #633044 !important;
          border-radius: 8px;
          outline: none;
          background: #070609 !important;
          color: #e4dce5 !important;
          -webkit-text-fill-color: #e4dce5;
          font-family: Inter, sans-serif;
          font-size: 11px !important;
          line-height: 1.5;
          box-shadow: inset 0 2px 5px #0009, 0 2px 0 #2a111b;
          resize: vertical;
          transition: border-color .18s ease, box-shadow .18s ease;
        }

        .sx-security-panel .sx-fingerprint-input::placeholder,
        .sx-security-panel textarea::placeholder,
        .sx-security-panel input::placeholder {
          color: #786d79 !important;
          -webkit-text-fill-color: #786d79;
          opacity: 1;
        }

        .sx-security-panel .sx-fingerprint-input:focus,
        .sx-security-panel textarea:focus,
        .sx-security-panel input:focus,
        .sx-security-panel select:focus {
          border-color: #b14b68 !important;
          box-shadow: 0 0 0 2px #85364e35, inset 0 2px 5px #0009;
        }

        .sx-security-panel button.sx-primary-button,
        .sx-security-panel button.sx-verify-button,
        .sx-security-panel button.sx-reset-verification-button,
        .sx-security-panel .sx-verification-actions button {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          min-height: 36px;
          max-width: 100%;
          margin: 6px 6px 2px 0;
          padding: 9px 12px;
          border: 1px solid #a04460 !important;
          border-radius: 8px !important;
          background: linear-gradient(180deg, #67283d 0%, #3a1421 100%) !important;
          color: #ffe5ec !important;
          font-family: Inter, sans-serif;
          font-size: 10px !important;
          font-weight: 650;
          line-height: 1.25;
          text-align: center;
          white-space: normal;
          cursor: pointer;
          box-shadow: 0 4px 0 #210b13, 0 7px 13px #0008, inset 0 1px 0 #ffffff20;
          transition: transform .15s ease, box-shadow .15s ease, filter .15s ease;
        }

        .sx-security-panel button.sx-primary-button:hover:not(:disabled),
        .sx-security-panel button.sx-verify-button:hover:not(:disabled),
        .sx-security-panel button.sx-reset-verification-button:hover:not(:disabled),
        .sx-security-panel .sx-verification-actions button:hover:not(:disabled) {
          filter: brightness(1.15);
          transform: translateY(-1px);
          box-shadow: 0 5px 0 #210b13, 0 9px 17px #0009, 0 0 12px #85364e35;
        }

        .sx-security-panel button.sx-primary-button:active:not(:disabled),
        .sx-security-panel button.sx-verify-button:active:not(:disabled),
        .sx-security-panel button.sx-reset-verification-button:active:not(:disabled),
        .sx-security-panel .sx-verification-actions button:active:not(:disabled) {
          transform: translateY(2px);
          box-shadow: 0 1px 0 #210b13, inset 0 2px 4px #0008;
        }

        .sx-security-panel button:disabled {
          opacity: .48;
          cursor: not-allowed;
          filter: grayscale(.25);
        }

        .sx-security-panel .sx-verification-actions {
          display: flex;
          flex-wrap: wrap;
          gap: 7px;
          margin-top: 8px;
        }

        .sx-security-panel .sx-verification-actions button {
          margin: 0;
        }

        @media (max-width: 1100px) {
          .sx-security-panel {
            width: min(310px, 86vw);
            min-width: 0;
          }
        }
      `}</style>

      {/* SIDEBAR */}

      <aside
        className={`sx-sidebar ${
          selectedChat && !mobileSidebarOpen
            ? "sx-sidebar-hidden"
            : ""
        }`}
      >
        <div className="sx-sidebar-header">
          <div className="sx-brand-row">
            <div className="sx-brand">
              SECURE<span>X</span>
            </div>

            <div className="sx-sidebar-actions">
              <button
                type="button"
                className="sx-icon-button"
                title="New conversation"
                aria-label="New conversation"
                onClick={() => {
                  setError("");
                  setShowNewChat(true);
                }}
              >
                +
              </button>

              <button
                type="button"
                className="sx-icon-button sx-group-create-button"
                title="Create a new group"
                aria-label="Create a new group"
                onClick={openNewGroup}
              >
                <GroupAddIcon />
              </button>
            </div>
          </div>

          <div className="sx-user-label">
            <span className="sx-user-name">
              {toDisplayText(currentUserName)}
            </span>

            <span className="sx-user-email">
              {toDisplayText(currentUserEmail)}
            </span>
          </div>

          <input
            className="sx-search"
            placeholder="Search conversations..."
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </div>

        <div className="sx-sidebar-section">
          <span>MESSAGES</span>
          <span>{conversations.length}</span>
        </div>

        <button
    type="button"
    className="security-center-nav"
    onClick={() => {
        setShowSecurityDashboard(true);
        setMobileSidebarOpen(false);
        setSecurityOpen(false);
    }}
>
    <i className="bi bi-shield-lock-fill"></i>
    <span>Security Command Center</span>
</button>

<div className="sx-conversation-list">
    {loading ? (
        <div className="sx-loading">
            Loading conversations...
        </div>
    ) : filteredConversations.length > 0 ? (
        filteredConversations.map((conversation) => (
            <React.Fragment key={getId(conversation)}>
                {renderConversation(conversation)}
            </React.Fragment>
        ))
    ) : (
        <div className="sx-loading">
            {search.trim()
                ? "No matching conversations found."
                : "No conversations available."}
        </div>
    )}
</div>

        <div className="sx-sidebar-footer">
          <div className="sx-account-info">
            <div className="sx-account-avatar">
              {currentUserInitial}
            </div>

            <div className="sx-account-details">
              <strong title={toDisplayText(currentUserName)}>
                {toDisplayText(currentUserName)}
              </strong>

              <small title={toDisplayText(currentUserEmail)}>
                {toDisplayText(currentUserEmail)}
              </small>
            </div>
          </div>

          <button
            type="button"
            className="sx-logout-button"
            onClick={handleLogout}
          >
            Logout
          </button>
        </div>
      </aside>

      {/* MAIN CHAT */}

      <main className="sx-chat-area">
        {showSecurityDashboard ? (
          <div style={{ width: "100%", height: "100%", overflowY: "auto" }}>
            <div style={{ padding: "12px 20px" }}>
              <button
                type="button"
                onClick={() => setShowSecurityDashboard(false)}
                className="sx-logout-button"
              >
                ← Back to Chat
              </button>
            </div>
            <SecurityCommandCenter />
          </div>
        ) : selectedChat ? (
          <>
            <header className="sx-chat-header">
              <div className="sx-chat-person">
                <button
                  type="button"
                  className="sx-mobile-back"
                  aria-label="Back to conversations"
                  onClick={() => setMobileSidebarOpen(true)}
                >
                  ←
                </button>

                <div className="sx-avatar">
                  {selectedIsGroup ? (
                    <GroupIcon />
                  ) : (
                    (
                      toDisplayText(
                        getConversationTitle(
                          selectedChat,
                          currentUserId
                        )
                      ) || "?"
                    ).charAt(0).toUpperCase()
                  )}
                </div>

                <div className="sx-chat-person-info">
                  <strong>
                    {toDisplayText(
                      getConversationTitle(
                        selectedChat,
                        currentUserId
                      )
                    )}
                  </strong>

                  <small>
                    {typingUser
                      ? `${toDisplayText(typingUser)} is typing...`
                      : toDisplayText(
                          getConversationSubtitle(
                            selectedChat,
                            currentUserId
                          )
                        ) || "End-to-end encrypted"}
                  </small>
                </div>
              </div>

              <div className="sx-chat-header-actions">
                <button
                  type="button"
                  title="Security information"
                  aria-label="Security information"
                  onClick={() => setSecurityOpen(!securityOpen)}
                >
                  ◈
                </button>

                {selectedIsGroup && (
                  <button
                    type="button"
                    title="Group information"
                    onClick={() => setShowGroupInfo(true)}
                  >
                    Group
                  </button>
                )}

                {selectedIsGroup && selectedIsAdmin && (
                  <button
                    type="button"
                    title="Add group members"
                    onClick={openAddGroupMembers}
                  >
                    + Member
                  </button>
                )}
              </div>
            </header>

            <div
              className="sx-messages"
              ref={messagesContainerRef}
              onScroll={(event) => {
                const element = event.currentTarget;

                const distanceFromBottom =
                  element.scrollHeight -
                  element.scrollTop -
                  element.clientHeight;

                shouldAutoScrollRef.current =
                  distanceFromBottom < 120;
              }}
            >
              {messagesLoading ? (
                <div className="sx-loading">
                  Decrypting messages...
                </div>
              ) : messages.length ? (
                messages.map(renderMessage)
              ) : (
                <div className="sx-empty-state">
                  <div className="sx-empty-logo">SX</div>

                  <h2>No messages yet</h2>

                  <p>
                    Send your first encrypted message to start chatting.
                  </p>
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>

            {typingUser && (
              <div className="sx-typing">
                {toDisplayText(typingUser)} is typing...
              </div>
            )}

            {/* COMPOSER AREA */}

            <div className="sx-composer-area">
              {renderReplyComposer()}
              {renderPendingAttachment()}
              {renderRecordingStatus()}

              {recordingError && (
                <div className="sx-recording-error">
                  {recordingError}
                  <button
                    type="button"
                    onClick={() => setRecordingError("")}
                  >
                    ×
                  </button>
                </div>
              )}
<form
  className="sx-composer"
  onSubmit={handleSendMessage}
>
  <input
    ref={attachmentInputRef}
    type="file"
    hidden
    accept="image/*,audio/*,video/*,.pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.csv"
    onChange={handleAttachmentSelect}
  />

  {/* ATTACH FILE */}
  <button
    type="button"
    className="sx-composer-button"
    title="Attach a file"
    aria-label="Attach a file"
    disabled={uploading || isRecording}
    onClick={() => attachmentInputRef.current?.click()}
  >
    ＋
  </button>

  {/* VOICE RECORDING */}
  <button
    type="button"
    className="sx-composer-button"
    title="Record voice message"
    aria-label="Record voice message"
    disabled={
      uploading ||
      isRecording ||
      Boolean(pendingAttachment)
    }
    onClick={() => startRecording("audio")}
  >
    <svg
      viewBox="0 0 24 24"
      width="21"
      height="21"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x="9" y="2" width="6" height="12" rx="3" />
      <path d="M5 10a7 7 0 0 0 14 0" />
      <path d="M12 17v5M8 22h8" />
    </svg>
  </button>

  {/* CAMERA OPTIONS */}
  <div
    className="sx-camera-menu-wrapper"
    style={{ position: "relative" }}
  >
    <button
      type="button"
      className="sx-composer-button"
      title="Camera options"
      aria-label="Camera options"
      aria-haspopup="true"
      aria-expanded={showCameraMenu}
      disabled={
        uploading ||
        isRecording ||
        Boolean(pendingAttachment)
      }
      onClick={() => setShowCameraMenu((previous) => !previous)}
    >
      <svg
        viewBox="0 0 24 24"
        width="21"
        height="21"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M14 5l1.5 2H20a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2h4l1.5-2z" />
        <circle cx="12" cy="13" r="3.5" />
      </svg>
    </button>

    {showCameraMenu && (
      <div
        role="menu"
        style={{
          position: "absolute",
          bottom: "52px",
          left: "0",
          width: "175px",
          background: "#171112",
          border: "1px solid #7d2639",
          borderRadius: "10px",
          padding: "6px",
          boxShadow: "0 8px 25px rgba(0,0,0,0.6)",
          zIndex: 1000,
        }}
      >
        <button
          type="button"
          role="menuitem"
          onClick={() => {
            setShowCameraMenu(false);
            startRecording("video");
          }}
          style={{
            display: "block",
            width: "100%",
            padding: "11px",
            border: "none",
            borderRadius: "6px",
            background: "transparent",
            color: "#fff",
            textAlign: "left",
            cursor: "pointer",
            fontSize: "13px",
          }}
        >
          ▷ Record video
        </button>

        <button
          type="button"
          role="menuitem"
          onClick={() => openCameraPreview()}
          style={{
            display: "block",
            width: "100%",
            padding: "11px",
            border: "none",
            borderRadius: "6px",
            background: "transparent",
            color: "#fff",
            textAlign: "left",
            cursor: "pointer",
            fontSize: "13px",
          }}
        >
          ◉ Take photo
        </button>
      </div>
    )}
  </div>

  {/* MESSAGE INPUT */}
  <textarea
    ref={messageInputRef}
    placeholder="Type a secure message..."
    value={messageText}
    disabled={isRecording || Boolean(pendingAttachment)}
    onChange={(event) => handleTyping(event.target.value)}
    onKeyDown={(event) => {
      if (
        event.key === "Enter" &&
        !event.shiftKey
      ) {
        event.preventDefault();
        handleSendMessage();
      }
    }}
  />

  {/* SEND MESSAGE */}
  <button
    type="submit"
    className="sx-composer-button"
    title="Send message"
    aria-label="Send message"
    disabled={
      sending ||
      uploading ||
      isRecording ||
      Boolean(pendingAttachment) ||
      !messageText.trim()
    }
  >
    {sending ? "…" : "➤"}
  </button>
</form>
            </div>
          </>
        ) : (
          renderEmptyState()
        )}

        {error && (
          <div className="sx-error">
            {toDisplayText(error)}

            <button
              type="button"
              aria-label="Dismiss error"
              onClick={() => setError("")}
              style={{
                marginLeft: 12,
                border: 0,
                background: "transparent",
                color: "white",
                cursor: "pointer",
              }}
            >
              ×
            </button>
          </div>
        )}
      </main>

{securityOpen && renderSecurityPanel()}
{renderNewChatModal()}
{renderGroupModal()}
{renderGroupManagement()}
{renderAttachmentPreview()}

{showCameraPreview && (
  <div
    style={{
      position: "fixed",
      inset: 0,
      background: "rgba(0,0,0,0.88)",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      zIndex: 10000,
      padding: "20px",
    }}
  >
    <div
      style={{
        width: "100%",
        maxWidth: "520px",
        background: "#171112",
        border: "1px solid #7d2639",
        borderRadius: "16px",
        padding: "18px",
        textAlign: "center",
      }}
    >
      <h3 style={{ color: "#fff", marginBottom: "15px" }}>
        SecureX Camera
      </h3>

      {/* CAMERA / PHOTO PREVIEW */}
      {capturedPhoto ? (
        <img
          src={capturedPhoto.previewUrl}
          alt="Captured photo preview"
          style={{
            width: "100%",
            maxHeight: "380px",
            objectFit: "contain",
            borderRadius: "10px",
          }}
        />
      ) : (
        <video
          ref={cameraVideoRef}
          autoPlay
          playsInline
          muted
          style={{
            width: "100%",
            maxHeight: "380px",
            objectFit: "cover",
            borderRadius: "10px",
            background: "#000",
          }}
        />
      )}
       {/* CAMERA CONTROLS */}
      <div className="sx-camera-controls">
        {isRecording && recordingType === "video" ? (
          <>
            <div className="sx-camera-recording-label">
              <span className="sx-camera-recording-dot" />
              RECORDING {formatRecordingTime(recordingSeconds)}
            </div>

            <button
              type="button"
              className="sx-camera-btn"
              onClick={cancelRecording}
            >
              Cancel
            </button>

            <button
              type="button"
              className="sx-camera-btn sx-camera-btn-danger"
              onClick={stopRecording}
            >
              Stop Recording
            </button>
          </>
        ) : capturedPhoto ? (
          <>
            <button
              type="button"
              className="sx-camera-btn"
              onClick={retakePhoto}
            >
              Retake
            </button>

            <button
              type="button"
              className="sx-camera-btn sx-camera-btn-primary"
              onClick={useCapturedPhoto}
            >
              Use Photo
            </button>
          </>
        ) : (
          <>
            <button
              type="button"
              className="sx-camera-btn"
              onClick={switchCamera}
            >
              Switch Camera
            </button>

            <button
              type="button"
              className="sx-camera-btn sx-camera-btn-primary"
              onClick={captureCameraPhoto}
            >
              Capture
            </button>

            <button
              type="button"
              className="sx-camera-btn"
              onClick={closeCameraPreview}
            >
              Cancel
            </button>
          </>
        )}
      </div>
    </div>
  </div>
)}
    </div>
  );
}

export default ChatLayout;