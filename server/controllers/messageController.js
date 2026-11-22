import mongoose from "mongoose";

import Message from "../models/Message.js";
import Conversation from "../models/Conversation.js";
import GroupKeyState from "../models/GroupKeyState.js";

/* =====================================================
   GENERAL HELPERS
===================================================== */

const getIO = (req) => req.app.get("io");

const getUserId = (user) =>
    String(user?._id || user?.id || "");

const normalizeId = (id) =>
    String(id || "").toLowerCase();

const getParticipantId = (participant) => {
    if (!participant) return "";

    if (typeof participant.toHexString === "function") {
        return participant.toHexString();
    }

    if (participant._id) {
        return getParticipantId(participant._id);
    }

    if (participant.userId) {
        return getParticipantId(participant.userId);
    }

    if (typeof participant === "string") {
        return participant;
    }

    if (typeof participant.id === "string") {
        return participant.id;
    }

    return String(participant);
};

const isValidId = (id) =>
    mongoose.Types.ObjectId.isValid(id);

const isParticipant = (conversation, userId) => {
    if (!conversation || !Array.isArray(conversation.participants)) {
        return false;
    }

    return conversation.participants.some(
        (participant) =>
            normalizeId(getParticipantId(participant)) ===
            normalizeId(userId)
    );
};

const unauthorizedResponse = (res) =>
    res.status(401).json({
        success: false,
        message: "Invalid authenticated user."
    });

/* =====================================================
   GROUP KEY ROTATION ENFORCEMENT
===================================================== */

const ensureGroupKeyReady = async (conversation) => {
    if (conversation.conversationType !== "group") {
        return null;
    }

    const state = await GroupKeyState.findOne({
        conversationId: conversation._id
    });

    if (!state) {
        return "Group encryption has not been initialized. An administrator must rotate the group key.";
    }

    const currentMembers = conversation.participants
        .map(getParticipantId)
        .map(normalizeId)
        .filter(Boolean)
        .sort();

    const previousMembers = (state.memberIds || [])
        .map(getParticipantId)
        .map(normalizeId)
        .filter(Boolean)
        .sort();

    const membershipChanged =
        currentMembers.length !== previousMembers.length ||
        currentMembers.some(
            (id, index) => id !== previousMembers[index]
        );

    if (membershipChanged) {
        state.rotationRequired = true;
        state.envelopes = [];
        await state.save();

        return "Group membership changed. Group-key rotation is required before sending messages.";
    }

    if (state.rotationRequired) {
        return "Group-key rotation is pending. Messages are temporarily blocked.";
    }

    if (
        !Number.isInteger(state.epoch) ||
        state.epoch < 1
    ) {
        return "Invalid group encryption epoch. Rotate the group key.";
    }

    const envelopes = state.envelopes || [];

    const envelopeMembers = [];
    for (const envelope of envelopes) {
        if (
            !envelope ||
            !envelope.userId ||
            typeof envelope.encryptedKey !== "string" ||
            !envelope.encryptedKey.trim()
        ) {
            state.rotationRequired = true;
            state.envelopes = [];
            await state.save();

            return "A group member has an invalid key envelope. Rotate the group key again.";
        }

        envelopeMembers.push(normalizeId(envelope.userId));
    }

    if (
        envelopeMembers.length !== currentMembers.length ||
        new Set(envelopeMembers).size !== currentMembers.length ||
        !currentMembers.every(
            (id) => envelopeMembers.includes(id)
        )
    ) {
        state.rotationRequired = true;
        state.envelopes = [];
        await state.save();

        return "Group key envelopes are incomplete. Rotate the group key again.";
    }

    return null;
};

/* =====================================================
   BASE64 VALIDATION
===================================================== */

const isValidBase64 = (value) => {
    if (
        typeof value !== "string" ||
        !value.length ||
        value.length % 4 !== 0
    ) {
        return false;
    }

    try {
        return Buffer.from(value, "base64").toString("base64") === value;
    } catch {
        return false;
    }
};

/* =====================================================
   ENCRYPTED PAYLOAD VALIDATION
===================================================== */

const validateEncryptedPayload = (body) => {
    const { ciphertext, iv } = body || {};

    if (!isValidBase64(ciphertext)) {
        return "Invalid encrypted message content.";
    }

    if (ciphertext.length > 10000000) {
        return "Encrypted message content is too large.";
    }

    if (
        !isValidBase64(iv) ||
        Buffer.from(iv, "base64").length !== 12
    ) {
        return "Invalid AES-GCM initialization vector.";
    }

    return null;
};

/* =====================================================
   CONVERSATION KEY ENVELOPE VALIDATION
===================================================== */

const validateConversationEnvelopes = (body, conversation) => {
    const isGroup = conversation.conversationType === "group";
    const envelopes = body.recipientKeyEnvelopes;

    if (!isGroup) {
        if (
            !isValidBase64(body.wrappedAESKey) ||
            !isValidBase64(body.senderWrappedAESKey)
        ) {
            return "Private conversations require sender and recipient key envelopes.";
        }

        if (Array.isArray(envelopes) && envelopes.length > 0) {
            return "Private conversations cannot use group key envelopes.";
        }

        return null;
    }

    if (!Array.isArray(envelopes) || envelopes.length === 0) {
        return "Group messages require encrypted keys for every member.";
    }

    const participantIds = conversation.participants.map(
        (participant) =>
            normalizeId(getParticipantId(participant))
    );

    if (participantIds.some((id) => !id)) {
        return "Invalid group participant ID.";
    }

    if (new Set(participantIds).size !== participantIds.length) {
        return "The group contains duplicate participant IDs.";
    }

    const envelopeIds = [];

    for (const envelope of envelopes) {
        if (
            !envelope ||
            !isValidId(envelope.userId) ||
            !isValidBase64(envelope.wrappedAESKey)
        ) {
            return "An invalid encrypted key envelope was provided.";
        }

        envelopeIds.push(normalizeId(envelope.userId));
    }

    if (envelopeIds.length !== participantIds.length) {
        return "An encrypted key envelope is missing or duplicated.";
    }

    if (new Set(envelopeIds).size !== envelopeIds.length) {
        return "Duplicate encrypted key envelopes are not allowed.";
    }

    if (
        !participantIds.every((id) => envelopeIds.includes(id))
    ) {
        return "Every group member must receive an encrypted key envelope.";
    }

    if (
        !envelopeIds.every((id) => participantIds.includes(id))
    ) {
        return "An encrypted key envelope has an invalid recipient.";
    }

    if (body.wrappedAESKey || body.senderWrappedAESKey) {
        return "Group messages must use recipient key envelopes.";
    }

    return null;
};

/* =====================================================
   ATTACHMENT VALIDATION
===================================================== */

const validateAttachment = (attachment) => {
    if (attachment === undefined || attachment === null) {
        return null;
    }

    if (
        typeof attachment !== "object" ||
        Array.isArray(attachment)
    ) {
        return "Invalid attachment metadata.";
    }

    const allowedFields = [
        "encryptedFileName",
        "encryptedMimeType",
        "encryptedFileSize",
        "storagePath",
        "fileIv"
    ];

    for (const key of Object.keys(attachment)) {
        if (!allowedFields.includes(key)) {
            return "Unsupported attachment metadata field.";
        }

        const value = attachment[key];

        if (
            value !== null &&
            value !== undefined &&
            typeof value !== "string"
        ) {
            return "Invalid attachment metadata.";
        }
    }

    const limits = {
        encryptedFileName: 4096,
        encryptedMimeType: 1024,
        encryptedFileSize: 512,
        storagePath: 2048,
        fileIv: 100
    };

    for (const [key, limit] of Object.entries(limits)) {
        const value = attachment[key];

        if (
            typeof value === "string" &&
            value.length > limit
        ) {
            return "Attachment metadata is too large.";
        }
    }

    if (attachment.fileIv) {
        if (
            !isValidBase64(attachment.fileIv) ||
            Buffer.from(attachment.fileIv, "base64").length !== 12
        ) {
            return "Invalid attachment initialization vector.";
        }
    }

    return null;
};

/* =====================================================
   ENCRYPTED DATABASE FIELDS
===================================================== */

const getEncryptedFields = (body) => ({
    ciphertext: body.ciphertext,
    iv: body.iv,
    wrappedAESKey: body.wrappedAESKey || null,
    senderWrappedAESKey: body.senderWrappedAESKey || null,

    recipientKeyEnvelopes: Array.isArray(body.recipientKeyEnvelopes)
        ? body.recipientKeyEnvelopes.map((item) => ({
            userId: item.userId,
            wrappedAESKey: item.wrappedAESKey
        }))
        : [],

    algorithm: "AES-256-GCM",
    keyEncryptionAlgorithm: "RSA-OAEP-SHA256"
});

/* =====================================================
   POPULATE MESSAGE
===================================================== */

const getPopulatedMessage = async (messageId) =>
    Message.findById(messageId).populate("sender", "name email");

/* =====================================================
   CONVERSATION ACTIVITY UPDATE
===================================================== */

const updateConversationAfterMessage = async (
    conversation,
    senderId,
    messageDate
) => {
    if (!Array.isArray(conversation.readStates)) {
        conversation.readStates = [];
    }

    const senderReadState = conversation.readStates.find(
        (state) =>
            normalizeId(state.userId) === normalizeId(senderId)
    );

    if (senderReadState) {
        senderReadState.lastReadAt = messageDate;
    } else {
        conversation.readStates.push({
            userId: senderId,
            lastReadAt: messageDate
        });
    }

    conversation.lastMessageAt = messageDate;
    conversation.updatedAt = messageDate;

    conversation.messageCount =
        Number(conversation.messageCount || 0) + 1;

    await conversation.save();
};

/* =====================================================
   SEND ENCRYPTED MESSAGE
===================================================== */

export const sendMessage = async (req, res) => {
    try {
        const userId = getUserId(req.user);

        if (!isValidId(userId)) {
            return unauthorizedResponse(res);
        }

        const {
            conversationId,
            clientMessageId,
            messageType = "text",
            attachment
        } = req.body || {};

        if (!isValidId(conversationId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid conversation ID."
            });
        }

        if (
            typeof clientMessageId !== "string" ||
            !clientMessageId.trim() ||
            clientMessageId.length > 100
        ) {
            return res.status(400).json({
                success: false,
                message: "A valid client message ID is required."
            });
        }

        const allowedTypes = [
            "text",
            "file",
            "image",
            "audio",
            "video"
        ];

        if (!allowedTypes.includes(messageType)) {
            return res.status(400).json({
                success: false,
                message: "Unsupported message type."
            });
        }

        const payloadError = validateEncryptedPayload(req.body);

        if (payloadError) {
            return res.status(400).json({
                success: false,
                message: payloadError
            });
        }

        const attachmentError = validateAttachment(attachment);

        if (attachmentError) {
            return res.status(400).json({
                success: false,
                message: attachmentError
            });
        }

        const conversation = await Conversation.findById(conversationId);

        if (!conversation || !isParticipant(conversation, userId)) {
            return res.status(403).json({
                success: false,
                message: "You are not a member of this conversation."
            });
        }

        const groupKeyError = await ensureGroupKeyReady(conversation);

        if (groupKeyError) {
            return res.status(409).json({
                success: false,
                code: "GROUP_KEY_ROTATION_REQUIRED",
                message: groupKeyError
            });
        }

        const envelopeError = validateConversationEnvelopes(
            req.body,
            conversation
        );

        if (envelopeError) {
            return res.status(400).json({
                success: false,
                message: envelopeError
            });
        }

        const trimmedClientMessageId = clientMessageId.trim();

        const existingMessage = await Message.findOne({
            conversationId,
            sender: userId,
            clientMessageId: trimmedClientMessageId
        });

        if (existingMessage) {
            const populatedExisting = await getPopulatedMessage(
                existingMessage._id
            );

            return res.status(200).json({
                success: true,
                message: "Message already received.",
                data: populatedExisting
            });
        }

        const message = await Message.create({
            conversationId,
            sender: userId,
            clientMessageId: trimmedClientMessageId,
            messageType,
            ...getEncryptedFields(req.body),
            attachment: attachment || undefined
        });

        const messageDate = message.createdAt || new Date();

        await updateConversationAfterMessage(
            conversation,
            userId,
            messageDate
        );

        const populatedMessage = await getPopulatedMessage(
            message._id
        );

        const io = getIO(req);

        io?.to(`conversation:${conversationId}`).emit(
            "new_encrypted_message",
            populatedMessage
        );

        conversation.participants.forEach((participant) => {
            io?.to(`user:${getParticipantId(participant)}`).emit(
                "conversation_activity",
                {
                    conversationId: String(conversationId),
                    lastMessageAt: conversation.lastMessageAt,
                    messageCount: conversation.messageCount,
                    senderId: userId
                }
            );
        });

        return res.status(201).json({
            success: true,
            message: "Encrypted message sent successfully.",
            data: populatedMessage
        });

    } catch (error) {
        if (error.code === 11000) {
            try {
                const existingMessage = await Message.findOne({
                    conversationId: req.body?.conversationId,
                    sender: getUserId(req.user),
                    clientMessageId: String(
                        req.body?.clientMessageId || ""
                    ).trim()
                });

                if (existingMessage) {
                    const populatedExisting =
                        await getPopulatedMessage(existingMessage._id);

                    return res.status(200).json({
                        success: true,
                        message: "Message already received.",
                        data: populatedExisting
                    });
                }
            } catch (duplicateError) {
                console.error(
                    "DUPLICATE MESSAGE RECOVERY ERROR:",
                    duplicateError
                );
            }
        }

        console.error("SEND MESSAGE ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to send encrypted message."
        });
    }
};

/* =====================================================
   GET CONVERSATION MESSAGES
===================================================== */

export const getMessages = async (req, res) => {
    try {
        const { conversationId } = req.params;
        const userId = getUserId(req.user);

        if (!isValidId(userId)) {
            return unauthorizedResponse(res);
        }

        if (!isValidId(conversationId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid conversation ID."
            });
        }

        const conversation = await Conversation.findById(conversationId);

        if (!conversation || !isParticipant(conversation, userId)) {
            return res.status(403).json({
                success: false,
                message: "You cannot access this conversation."
            });
        }

        const latestMessages = await Message.find({
            conversationId,
            deletedFor: { $ne: userId }
        })
            .populate("sender", "name email")
            .sort({ createdAt: -1, _id: -1 })
            .limit(500)
            .lean();

        const messages = latestMessages.reverse();

        return res.status(200).json({
            success: true,
            count: messages.length,
            messages
        });

    } catch (error) {
        console.error("GET MESSAGES ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to retrieve messages."
        });
    }
};

/* =====================================================
   MARK CONVERSATION AS READ
===================================================== */

export const markConversationRead = async (req, res) => {
    try {
        const { conversationId } = req.params;
        const userId = getUserId(req.user);

        if (!isValidId(userId)) {
            return unauthorizedResponse(res);
        }

        if (!isValidId(conversationId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid conversation ID."
            });
        }

        const conversation = await Conversation.findById(conversationId);

        if (!conversation || !isParticipant(conversation, userId)) {
            return res.status(403).json({
                success: false,
                message: "You cannot access this conversation."
            });
        }

        if (!Array.isArray(conversation.readStates)) {
            conversation.readStates = [];
        }

        const readAt = new Date();

        let readState = conversation.readStates.find(
            (state) =>
                normalizeId(state.userId) === normalizeId(userId)
        );

        if (readState) {
            readState.lastReadAt = readAt;
        } else {
            conversation.readStates.push({
                userId,
                lastReadAt: readAt
            });
        }

        await conversation.save();

        const io = getIO(req);

        const readPayload = {
            conversationId,
            userId,
            lastReadAt: readAt
        };

        io?.to(`conversation:${conversationId}`).emit(
            "conversation_read",
            readPayload
        );

        io?.to(`user:${userId}`).emit(
            "conversation_read",
            readPayload
        );

        return res.status(200).json({
            success: true,
            message: "Conversation marked as read.",
            conversationId,
            lastReadAt: readAt,
            unreadCount: 0
        });

    } catch (error) {
        console.error("MARK CONVERSATION READ ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to mark conversation as read."
        });
    }
};

/* =====================================================
   EDIT ENCRYPTED MESSAGE
===================================================== */

export const editMessage = async (req, res) => {
    try {
        const { messageId } = req.params;
        const userId = getUserId(req.user);

        if (!isValidId(userId)) {
            return unauthorizedResponse(res);
        }

        if (!isValidId(messageId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid message ID."
            });
        }

        const message = await Message.findById(messageId);

        if (!message) {
            return res.status(404).json({
                success: false,
                message: "Message not found."
            });
        }

        if (message.messageType === "system") {
            return res.status(400).json({
                success: false,
                message: "System messages cannot be edited."
            });
        }

        if (normalizeId(message.sender) !== normalizeId(userId)) {
            return res.status(403).json({
                success: false,
                message: "You can only edit your own messages."
            });
        }

        const conversation = await Conversation.findById(
            message.conversationId
        );

        if (!conversation || !isParticipant(conversation, userId)) {
            return res.status(403).json({
                success: false,
                message: "You cannot edit this message."
            });
        }

        const groupKeyError = await ensureGroupKeyReady(conversation);

        if (groupKeyError) {
            return res.status(409).json({
                success: false,
                code: "GROUP_KEY_ROTATION_REQUIRED",
                message: groupKeyError
            });
        }

        const payloadError = validateEncryptedPayload(req.body);

        if (payloadError) {
            return res.status(400).json({
                success: false,
                message: payloadError
            });
        }

        const envelopeError = validateConversationEnvelopes(
            req.body,
            conversation
        );

        if (envelopeError) {
            return res.status(400).json({
                success: false,
                message: envelopeError
            });
        }

        Object.assign(message, getEncryptedFields(req.body));

        message.isEdited = true;
        message.editedAt = new Date();

        await message.save();

        const populatedMessage = await getPopulatedMessage(
            message._id
        );

        getIO(req)
            ?.to(`conversation:${message.conversationId}`)
            .emit("message_edited", populatedMessage);

        return res.status(200).json({
            success: true,
            message: "Message updated successfully.",
            data: populatedMessage
        });

    } catch (error) {
        console.error("EDIT MESSAGE ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to edit message."
        });
    }
};

/* =====================================================
   DELETE MESSAGE FOR CURRENT USER
===================================================== */

export const deleteMessageForMe = async (req, res) => {
    try {
        const { messageId } = req.params;
        const userId = getUserId(req.user);

        if (!isValidId(userId)) {
            return unauthorizedResponse(res);
        }

        if (!isValidId(messageId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid message ID."
            });
        }

        const message = await Message.findById(messageId);

        if (!message) {
            return res.status(404).json({
                success: false,
                message: "Message not found."
            });
        }

        const conversation = await Conversation.findById(
            message.conversationId
        );

        if (!conversation || !isParticipant(conversation, userId)) {
            return res.status(403).json({
                success: false,
                message: "You cannot delete this message."
            });
        }

        await Message.updateOne(
            { _id: messageId },
            { $addToSet: { deletedFor: userId } }
        );

        getIO(req)
            ?.to(`user:${userId}`)
            .emit("message_deleted_for_me", {
                messageId,
                userId
            });

        return res.status(200).json({
            success: true,
            message: "Message deleted from your chat."
        });

    } catch (error) {
        console.error("DELETE FOR ME ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to delete message."
        });
    }
};

/* =====================================================
   DELETE MESSAGE FOR EVERYONE
===================================================== */

export const deleteMessageForEveryone = async (req, res) => {
    try {
        const { messageId } = req.params;
        const userId = getUserId(req.user);

        if (!isValidId(userId)) {
            return unauthorizedResponse(res);
        }

        if (!isValidId(messageId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid message ID."
            });
        }

        const message = await Message.findById(messageId);

        if (!message) {
            return res.status(404).json({
                success: false,
                message: "Message not found."
            });
        }

        if (normalizeId(message.sender) !== normalizeId(userId)) {
            return res.status(403).json({
                success: false,
                message: "You can only delete your own messages for everyone."
            });
        }

        const conversationId = String(message.conversationId);

        const conversation = await Conversation.findById(
            conversationId
        );

        if (!conversation || !isParticipant(conversation, userId)) {
            return res.status(403).json({
                success: false,
                message: "You cannot delete this message."
            });
        }

        const deletedMessage = await Message.findOneAndDelete({
            _id: messageId,
            sender: userId
        });

        if (!deletedMessage) {
            return res.status(404).json({
                success: false,
                message: "Message no longer exists."
            });
        }

        conversation.messageCount = Math.max(
            0,
            Number(conversation.messageCount || 0) - 1
        );

        const latestMessage = await Message.findOne({
            conversationId
        })
            .sort({ createdAt: -1, _id: -1 })
            .select("createdAt");

        conversation.lastMessageAt =
            latestMessage?.createdAt || null;

        conversation.updatedAt = new Date();

        await conversation.save();

        const io = getIO(req);

        io?.to(`conversation:${conversationId}`).emit(
            "message_deleted_for_everyone",
            {
                messageId,
                conversationId
            }
        );

        conversation.participants.forEach((participant) => {
            io?.to(`user:${getParticipantId(participant)}`).emit(
                "conversation_activity",
                {
                    conversationId,
                    lastMessageAt: conversation.lastMessageAt,
                    messageCount: conversation.messageCount,
                    deleted: true
                }
            );
        });

        return res.status(200).json({
            success: true,
            message: "Message deleted for everyone."
        });

    } catch (error) {
        console.error("DELETE FOR EVERYONE ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to delete message for everyone."
        });
    }
};