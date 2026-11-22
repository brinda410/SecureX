import fs from "fs/promises";
import path from "path";
import mongoose from "mongoose";

import Conversation from "../models/Conversation.js";
import User from "../models/User.js";
import Message from "../models/Message.js";
import EncryptedAttachment from "../models/EncryptedAttachment.js";
import GroupKeyState from "../models/GroupKeyState.js";

// ======================================================
// HELPERS
// ======================================================

const getId = (value) => {
    if (!value) return "";

    if (typeof value.toHexString === "function") {
        return value.toHexString();
    }

    if (value._id) {
        return getId(value._id);
    }

    if (typeof value === "string") {
        return value;
    }

    if (typeof value.id === "string") {
        return value.id;
    }

    return String(value);
};

const normalizeId = (value) =>
    getId(value).toLowerCase();

const isValidGmail = (email) =>
    /^[a-zA-Z0-9._%+-]+@gmail\.com$/i.test(email);

const isParticipant = (conversation, userId) =>
    conversation.participants.some(
        (participant) =>
            normalizeId(participant) === normalizeId(userId)
    );

const getAdminIds = (conversation) => {
    const ids = new Set();

    if (conversation.groupAdmin) {
        ids.add(normalizeId(conversation.groupAdmin));
    }

    if (Array.isArray(conversation.groupAdmins)) {
        conversation.groupAdmins.forEach((admin) => {
            if (admin) {
                ids.add(normalizeId(admin));
            }
        });
    }

    return ids;
};

const isAdmin = (conversation, userId) =>
    getAdminIds(conversation).has(normalizeId(userId));

const setGroupAdmins = (conversation, adminIds) => {
    const participantIds = new Set(
        conversation.participants.map(normalizeId)
    );

    const validAdmins = [
        ...new Set(
            adminIds
                .map(normalizeId)
                .filter(
                    (id) => id && participantIds.has(id)
                )
        )
    ];

    conversation.groupAdmins = validAdmins;
    conversation.groupAdmin = validAdmins[0] || null;
};

const normalizeGroupAdmins = (conversation) => {
    if (conversation.conversationType !== "group") {
        return;
    }

    let admins = [];

    if (
        Array.isArray(conversation.groupAdmins) &&
        conversation.groupAdmins.length > 0
    ) {
        admins = conversation.groupAdmins.map(normalizeId);
    } else if (conversation.groupAdmin) {
        admins = [normalizeId(conversation.groupAdmin)];
    } else if (conversation.createdBy) {
        admins = [normalizeId(conversation.createdBy)];
    }

    setGroupAdmins(conversation, admins);
};

const getIO = (req) => req.app.get("io");

const populateConversation = (id) =>
    Conversation.findById(id)
        .populate(
            "participants",
            "name email isOnline lastSeen publicKey"
        )
        .populate("groupAdmin", "name email")
        .populate("groupAdmins", "name email");

const initializeReadStates = (
    participantIds,
    date = new Date()
) =>
    participantIds.map((userId) => ({
        userId,
        lastReadAt: date
    }));

const validateConversationId = (id) =>
    mongoose.Types.ObjectId.isValid(id);

const emitConversationCreated = (
    io,
    participantIds,
    conversation
) => {
    participantIds.forEach((participantId) => {
        io?.to(`user:${getId(participantId)}`).emit(
            "conversation_created",
            conversation
        );
    });
};

const emitConversationRemoved = (
    io,
    participantIds,
    conversationId
) => {
    participantIds.forEach((participantId) => {
        io?.to(`user:${getId(participantId)}`).emit(
            "conversation_removed",
            {
                conversationId: String(conversationId)
            }
        );
    });
};

// ======================================================
// GROUP KEY INVALIDATION
// ======================================================

// Every membership change invalidates the existing group key.
// A fresh key must be generated and distributed to current members.
const invalidateGroupKey = async (conversation) => {
    if (
        !conversation ||
        conversation.conversationType !== "group"
    ) {
        return;
    }

    const memberIds = conversation.participants.map(
        (participant) => getId(participant)
    );

    await GroupKeyState.findOneAndUpdate(
        {
            conversationId: conversation._id
        },
        {
            $set: {
                memberIds,
                envelopes: [],
                rotationRequired: true,
                rotatedBy: null,
                rotatedAt: null
            },
            $setOnInsert: {
                epoch: 0
            }
        },
        {
            upsert: true,
            new: true,
            setDefaultsOnInsert: true
        }
    );
};

// ======================================================
// PERSISTENT GROUP ACTIVITY EVENTS
// ======================================================

const persistGroupSystemEvent = async ({
    io,
    conversationId,
    actorId,
    type,
    targetUserId = null,
    previousAdminId = null,
    newAdminId = null
}) => {
    const allowedTypes = [
        "group_created",
        "member_added",
        "member_removed",
        "member_left",
        "admin_changed"
    ];

    if (!allowedTypes.includes(type)) {
        throw new Error("Invalid group system event type.");
    }

    const event = await Message.create({
        conversationId,
        sender: actorId,
        clientMessageId: `system:${new mongoose.Types.ObjectId()}`,
        messageType: "system",
        systemEvent: {
            type,
            actorId,
            targetUserId,
            previousAdminId,
            newAdminId
        }
    });

    await Conversation.updateOne(
        { _id: conversationId },
        {
            $set: {
                lastMessageAt: event.createdAt
            },
            $inc: {
                messageCount: 1
            }
        }
    );

    const populatedEvent = await Message.findById(event._id)
        .populate("sender", "name email")
        .populate("systemEvent.actorId", "name email")
        .populate("systemEvent.targetUserId", "name email")
        .populate("systemEvent.previousAdminId", "name email")
        .populate("systemEvent.newAdminId", "name email");

    io?.to(`conversation:${conversationId}`).emit(
        "new_encrypted_message",
        populatedEvent
    );

    return populatedEvent;
};

// ======================================================
// UNREAD COUNT
// ======================================================

const getUnreadCount = async (conversation, userId) => {
    const readState = conversation.readStates?.find(
        (state) =>
            normalizeId(state.userId) === normalizeId(userId)
    );

    const query = {
        conversationId: conversation._id,
        sender: { $ne: userId },
        deletedFor: { $ne: userId }
    };

    if (readState?.lastReadAt) {
        query.createdAt = {
            $gt: readState.lastReadAt
        };
    }

    return Message.countDocuments(query);
};

// ======================================================
// CREATE PRIVATE CONVERSATION
// ======================================================

export const createConversation = async (req, res) => {
    try {
        const recipientEmail = String(
            req.body.recipientEmail || ""
        ).trim().toLowerCase();

        if (!isValidGmail(recipientEmail)) {
            return res.status(400).json({
                success: false,
                message: "Enter a valid Gmail address."
            });
        }

        const recipient = await User.findOne({
            email: recipientEmail
        });

        if (!recipient) {
            return res.status(404).json({
                success: false,
                message: "This user is not registered on SecureX."
            });
        }

        if (normalizeId(recipient) === normalizeId(req.user)) {
            return res.status(400).json({
                success: false,
                message: "You cannot chat with yourself."
            });
        }

        const existing = await Conversation.findOne({
            conversationType: "private",
            participants: {
                $all: [req.user._id, recipient._id],
                $size: 2
            }
        });

        if (existing) {
            return res.status(200).json({
                success: true,
                message: "Conversation already exists.",
                conversation: await populateConversation(existing._id)
            });
        }

        const participantIds = [
            req.user._id,
            recipient._id
        ];

        const now = new Date();

        const created = await Conversation.create({
            participants: participantIds,
            conversationType: "private",
            createdBy: req.user._id,
            readStates: initializeReadStates(participantIds, now)
        });

        const conversation = await populateConversation(created._id);

        return res.status(201).json({
            success: true,
            message: "Private conversation created.",
            conversation
        });

    } catch (error) {
        console.error("CREATE PRIVATE CHAT ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to create private conversation."
        });
    }
};

// ======================================================
// GET MY CONVERSATIONS
// ======================================================

export const getMyConversations = async (req, res) => {
    try {
        const userId = req.user._id;

        console.log("SECUREX DEBUG USER:", {
            id: String(userId),
            email: req.user.email
        });

        console.log(
            "SECUREX DEBUG CONVERSATION COUNT:",
            await Conversation.countDocuments({
                participants: userId
            })
        );

        const conversations = await Conversation.find({
            participants: userId
        })
            .populate(
                "participants",
                "name email isOnline lastSeen publicKey"
            )
            .populate("groupAdmin", "name email")
            .populate("groupAdmins", "name email")
            .lean();

        const enriched = await Promise.all(
            conversations.map(async (conversation) => {
                const [unreadCount, messageCount] =
                    await Promise.all([
                        getUnreadCount(conversation, userId),
                        Message.countDocuments({
                            conversationId: conversation._id
                        })
                    ]);

                return {
                    ...conversation,
                    unreadCount,
                    messageCount,
                    lastMessageAt:
                        conversation.lastMessageAt ||
                        conversation.updatedAt ||
                        conversation.createdAt,
                    lastMessagePreview: null
                };
            })
        );

        enriched.sort(
            (a, b) =>
                new Date(b.lastMessageAt).getTime() -
                new Date(a.lastMessageAt).getTime()
        );

        return res.status(200).json({
            success: true,
            count: enriched.length,
            conversations: enriched
        });

    } catch (error) {
        console.error("GET CONVERSATIONS ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to retrieve conversations."
        });
    }
};

// ======================================================
// CREATE GROUP
// ======================================================

export const createGroup = async (req, res) => {
    try {
        const groupName = String(
            req.body.groupName || ""
        ).trim();

        const memberEmails =
            req.body.memberEmails ?? req.body.participantEmails;

        if (groupName.length < 2 || groupName.length > 100) {
            return res.status(400).json({
                success: false,
                message: "Group name must contain 2–100 characters."
            });
        }

        if (
            !Array.isArray(memberEmails) ||
            memberEmails.length < 1 ||
            memberEmails.length > 49
        ) {
            return res.status(400).json({
                success: false,
                message: "Add at least one other member. Groups support up to 50 members."
            });
        }

        const emails = [
            ...new Set(
                memberEmails
                    .map((email) =>
                        String(email).trim().toLowerCase()
                    )
                    .filter(Boolean)
            )
        ];

        if (emails.some((email) => !isValidGmail(email))) {
            return res.status(400).json({
                success: false,
                message: "All group members must have valid Gmail addresses."
            });
        }

        const users = await User.find({
            email: { $in: emails }
        }).select("_id name email publicKey");

        if (users.length !== emails.length) {
            const found = new Set(
                users.map((user) => user.email)
            );

            return res.status(404).json({
                success: false,
                message: "Some users are not registered on SecureX.",
                missingEmails: emails.filter(
                    (email) => !found.has(email)
                )
            });
        }

        const usersWithoutKeys = users
            .filter(
                (user) =>
                    typeof user.publicKey !== "string" ||
                    !user.publicKey.trim()
            )
            .map((user) => user.email);

        if (usersWithoutKeys.length) {
            return res.status(409).json({
                success: false,
                message: "Some members have not initialized their encryption keys. Ask them to log in first.",
                missingKeyEmails: usersWithoutKeys
            });
        }

        const participantIds = [
            req.user._id,
            ...users
                .filter(
                    (user) =>
                        normalizeId(user) !== normalizeId(req.user)
                )
                .map((user) => user._id)
        ];

        if (
            participantIds.length < 2 ||
            participantIds.length > 50
        ) {
            return res.status(400).json({
                success: false,
                message: "A group must contain 2–50 different members."
            });
        }

        const now = new Date();

        const group = await Conversation.create({
            groupName,
            conversationType: "group",
            participants: participantIds,
            groupAdmin: req.user._id,
            groupAdmins: [req.user._id],
            createdBy: req.user._id,
            readStates: initializeReadStates(participantIds, now)
        });

        // A new group starts with key rotation required.
        await invalidateGroupKey(group);

        const io = getIO(req);

        await persistGroupSystemEvent({
            io,
            conversationId: group._id,
            actorId: req.user._id,
            type: "group_created"
        });

        const conversation = await populateConversation(group._id);

        emitConversationCreated(
            io,
            participantIds,
            conversation
        );

        return res.status(201).json({
            success: true,
            message: "Group created successfully.",
            conversation
        });

    } catch (error) {
        console.error("CREATE GROUP ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to create group."
        });
    }
};

// ======================================================
// ADD GROUP MEMBER
// ======================================================

export const addGroupMember = async (req, res) => {
    try {
        const { conversationId } = req.params;

        if (!validateConversationId(conversationId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid conversation ID."
            });
        }

        const conversation = await Conversation.findById(conversationId);

        if (
            !conversation ||
            conversation.conversationType !== "group"
        ) {
            return res.status(404).json({
                success: false,
                message: "Group not found."
            });
        }

        normalizeGroupAdmins(conversation);

        if (!isParticipant(conversation, req.user._id)) {
            return res.status(403).json({
                success: false,
                message: "You are not a group member."
            });
        }

        if (!isAdmin(conversation, req.user._id)) {
            return res.status(403).json({
                success: false,
                message: "Only group admins can add members."
            });
        }

        const email = String(req.body.email || "")
            .trim()
            .toLowerCase();

        if (!isValidGmail(email)) {
            return res.status(400).json({
                success: false,
                message: "Enter a valid Gmail address."
            });
        }

        const user = await User.findOne({ email })
            .select("_id name email publicKey");

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User is not registered on SecureX."
            });
        }

        if (isParticipant(conversation, user._id)) {
            return res.status(409).json({
                success: false,
                message: "This user is already in the group."
            });
        }

        if (conversation.participants.length >= 50) {
            return res.status(400).json({
                success: false,
                message: "The group has reached its 50-member limit."
            });
        }

        if (
            typeof user.publicKey !== "string" ||
            !user.publicKey.trim()
        ) {
            return res.status(409).json({
                success: false,
                message: "This user has not initialized encryption keys."
            });
        }

        conversation.participants.push(user._id);

        conversation.readStates.push({
            userId: user._id,
            lastReadAt: new Date()
        });

        await conversation.save();

        // Invalidate the previous group key after membership changes.
        await invalidateGroupKey(conversation);

        const io = getIO(req);

        await persistGroupSystemEvent({
            io,
            conversationId,
            actorId: req.user._id,
            type: "member_added",
            targetUserId: user._id
        });

        const updated = await populateConversation(conversationId);

        io?.to(`user:${getId(user)}`).emit(
            "conversation_created",
            updated
        );

        io?.to(`conversation:${conversationId}`).emit(
            "group_member_added",
            {
                conversationId,
                user: {
                    _id: user._id,
                    name: user.name,
                    email: user.email
                },
                conversation: updated
            }
        );

        return res.status(200).json({
            success: true,
            message: "Member added successfully. Group key rotation is required.",
            conversation: updated
        });

    } catch (error) {
        console.error("ADD GROUP MEMBER ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to add group member."
        });
    }
};

// ======================================================
// REMOVE GROUP MEMBER
// ======================================================

export const removeGroupMember = async (req, res) => {
    try {
        const { conversationId, userId } = req.params;

        if (
            !validateConversationId(conversationId) ||
            !validateConversationId(userId)
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid ID."
            });
        }

        const conversation = await Conversation.findById(conversationId);

        if (
            !conversation ||
            conversation.conversationType !== "group"
        ) {
            return res.status(404).json({
                success: false,
                message: "Group not found."
            });
        }

        normalizeGroupAdmins(conversation);

        if (!isParticipant(conversation, req.user._id)) {
            return res.status(403).json({
                success: false,
                message: "You are not a group member."
            });
        }

        if (!isAdmin(conversation, req.user._id)) {
            return res.status(403).json({
                success: false,
                message: "Only group admins can remove members."
            });
        }

        if (!isParticipant(conversation, userId)) {
            return res.status(404).json({
                success: false,
                message: "This user is not in the group."
            });
        }

        const targetIsAdmin = isAdmin(conversation, userId);
        const adminIds = [...getAdminIds(conversation)];

        if (targetIsAdmin && adminIds.length <= 1) {
            return res.status(400).json({
                success: false,
                message: "You cannot remove the last group admin."
            });
        }

        const io = getIO(req);

        await persistGroupSystemEvent({
            io,
            conversationId,
            actorId: req.user._id,
            type: "member_removed",
            targetUserId: userId
        });

        conversation.participants =
            conversation.participants.filter(
                (participant) =>
                    normalizeId(participant) !== normalizeId(userId)
            );

        conversation.readStates =
            conversation.readStates.filter(
                (state) =>
                    normalizeId(state.userId) !== normalizeId(userId)
            );

        if (targetIsAdmin) {
            const remainingAdmins = adminIds.filter(
                (id) => id !== normalizeId(userId)
            );

            setGroupAdmins(conversation, remainingAdmins);
        } else {
            normalizeGroupAdmins(conversation);
        }

        await conversation.save();

        // The removed member must not retain access through the old group key.
        await invalidateGroupKey(conversation);

        const updated = await populateConversation(conversationId);

        io?.to(`user:${userId}`).emit(
            "conversation_removed",
            { conversationId }
        );

        io?.in(`user:${userId}`).socketsLeave(
            `conversation:${conversationId}`
        );

        io?.to(`conversation:${conversationId}`).emit(
            "group_member_removed",
            {
                conversationId,
                userId,
                conversation: updated
            }
        );

        return res.status(200).json({
            success: true,
            message: "Member removed successfully. Group key rotation is required.",
            conversation: updated
        });

    } catch (error) {
        console.error("REMOVE GROUP MEMBER ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to remove member."
        });
    }
};

// ======================================================
// LEAVE GROUP
// ======================================================

export const leaveGroup = async (req, res) => {
    try {
        const { conversationId } = req.params;

        if (!validateConversationId(conversationId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid conversation ID."
            });
        }

        const conversation = await Conversation.findById(conversationId);

        if (
            !conversation ||
            conversation.conversationType !== "group"
        ) {
            return res.status(404).json({
                success: false,
                message: "Group not found."
            });
        }

        normalizeGroupAdmins(conversation);

        if (!isParticipant(conversation, req.user._id)) {
            return res.status(403).json({
                success: false,
                message: "You are not a member of this group."
            });
        }

        const wasAdmin = isAdmin(conversation, req.user._id);
        const adminIds = [...getAdminIds(conversation)];

        if (wasAdmin && adminIds.length <= 1) {
            return res.status(400).json({
                success: false,
                message: "Promote another member to admin before leaving."
            });
        }

        const io = getIO(req);

        await persistGroupSystemEvent({
            io,
            conversationId,
            actorId: req.user._id,
            type: "member_left"
        });

        conversation.participants =
            conversation.participants.filter(
                (participant) =>
                    normalizeId(participant) !== normalizeId(req.user)
            );

        conversation.readStates =
            conversation.readStates.filter(
                (state) =>
                    normalizeId(state.userId) !== normalizeId(req.user)
            );

        if (wasAdmin) {
            setGroupAdmins(
                conversation,
                adminIds.filter(
                    (id) => id !== normalizeId(req.user._id)
                )
            );
        } else {
            normalizeGroupAdmins(conversation);
        }

        await conversation.save();

        // Rotate the group key so the departed member cannot access future messages.
        await invalidateGroupKey(conversation);

        const updated = await populateConversation(conversationId);

        io?.to(`user:${getId(req.user)}`).emit(
            "conversation_removed",
            { conversationId }
        );

        io?.in(`user:${getId(req.user)}`).socketsLeave(
            `conversation:${conversationId}`
        );

        io?.to(`conversation:${conversationId}`).emit(
            "group_member_removed",
            {
                conversationId,
                userId: getId(req.user),
                conversation: updated
            }
        );

        return res.status(200).json({
            success: true,
            message: "You left the group."
        });

    } catch (error) {
        console.error("LEAVE GROUP ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to leave group."
        });
    }
};

// ======================================================
// PROMOTE GROUP ADMIN
// ======================================================

export const transferGroupAdmin = async (req, res) => {
    try {
        const { conversationId } = req.params;
        const { newAdminId } = req.body;

        if (
            !validateConversationId(conversationId) ||
            !validateConversationId(newAdminId)
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid ID."
            });
        }

        const conversation = await Conversation.findById(conversationId);

        if (
            !conversation ||
            conversation.conversationType !== "group"
        ) {
            return res.status(404).json({
                success: false,
                message: "Group not found."
            });
        }

        normalizeGroupAdmins(conversation);

        if (!isParticipant(conversation, req.user._id)) {
            return res.status(403).json({
                success: false,
                message: "You are not a group member."
            });
        }

        if (!isAdmin(conversation, req.user._id)) {
            return res.status(403).json({
                success: false,
                message: "Only a group admin can promote another admin."
            });
        }

        if (!isParticipant(conversation, newAdminId)) {
            return res.status(400).json({
                success: false,
                message: "The new admin must already be a group member."
            });
        }

        if (isAdmin(conversation, newAdminId)) {
            return res.status(400).json({
                success: false,
                message: "This member is already an admin."
            });
        }

        const previousAdminId = conversation.groupAdmin;

        const currentAdmins = [...getAdminIds(conversation)];

        setGroupAdmins(conversation, [
            ...currentAdmins,
            newAdminId
        ]);

        await conversation.save();

        const io = getIO(req);

        await persistGroupSystemEvent({
            io,
            conversationId,
            actorId: req.user._id,
            type: "admin_changed",
            previousAdminId,
            newAdminId
        });

        const updated = await populateConversation(conversationId);

        io?.to(`conversation:${conversationId}`).emit(
            "group_admin_changed",
            {
                conversationId,
                newAdminId,
                conversation: updated
            }
        );

        return res.status(200).json({
            success: true,
            message: "New group admin added successfully.",
            conversation: updated
        });

    } catch (error) {
        console.error("TRANSFER ADMIN ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to promote group admin."
        });
    }
};

// ======================================================
// DISMISS ANOTHER GROUP ADMIN
// ======================================================

export const dismissGroupAdmin = async (req, res) => {
    try {
        const { conversationId, userId } = req.params;
        const currentUserId = normalizeId(req.user._id);
        const targetId = normalizeId(userId);

        if (
            !validateConversationId(conversationId) ||
            !validateConversationId(userId)
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid conversation or user ID."
            });
        }

        const conversation = await Conversation.findById(conversationId);

        if (!conversation || conversation.conversationType !== "group") {
            return res.status(404).json({
                success: false,
                message: "Group not found."
            });
        }

        normalizeGroupAdmins(conversation);

        if (!isParticipant(conversation, currentUserId)) {
            return res.status(403).json({
                success: false,
                message: "You are not a member of this group."
            });
        }

        if (!isAdmin(conversation, currentUserId)) {
            return res.status(403).json({
                success: false,
                message: "Only group admins can dismiss another admin."
            });
        }

        if (!isParticipant(conversation, targetId)) {
            return res.status(404).json({
                success: false,
                message: "Group member not found."
            });
        }

        if (currentUserId === targetId) {
            return res.status(400).json({
                success: false,
                message: "Use resign as admin to remove your own admin role."
            });
        }

        const adminIds = [...getAdminIds(conversation)];

        if (!adminIds.includes(targetId)) {
            return res.status(400).json({
                success: false,
                message: "This member is not a group admin."
            });
        }

        if (adminIds.length <= 1) {
            return res.status(400).json({
                success: false,
                message: "The last group admin cannot be dismissed."
            });
        }

        const remainingAdmins = adminIds.filter(
            (id) => id !== targetId
        );

        setGroupAdmins(conversation, remainingAdmins);

        await conversation.save();

        const io = getIO(req);

        await persistGroupSystemEvent({
            io,
            conversationId: conversation._id,
            actorId: req.user._id,
            type: "admin_changed",
            previousAdminId: targetId,
            newAdminId: remainingAdmins[0]
        });

        const updatedConversation = await populateConversation(
            conversation._id
        );

        io?.to(`conversation:${conversationId}`).emit(
            "group_admin_changed",
            {
                conversationId,
                groupAdmins: remainingAdmins,
                conversation: updatedConversation
            }
        );

        return res.status(200).json({
            success: true,
            message: "Group admin dismissed successfully.",
            conversation: updatedConversation
        });

    } catch (error) {
        console.error("Dismiss group admin error:", error);

        return res.status(500).json({
            success: false,
            message: "Failed to dismiss group admin."
        });
    }
};

// ======================================================
// RESIGN AS GROUP ADMIN WITHOUT LEAVING
// ======================================================

export const resignGroupAdmin = async (req, res) => {
    try {
        const { conversationId } = req.params;
        const currentUserId = normalizeId(req.user._id);

        if (!validateConversationId(conversationId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid conversation ID."
            });
        }

        const conversation = await Conversation.findById(conversationId);

        if (!conversation || conversation.conversationType !== "group") {
            return res.status(404).json({
                success: false,
                message: "Group not found."
            });
        }

        normalizeGroupAdmins(conversation);

        if (!isParticipant(conversation, currentUserId)) {
            return res.status(403).json({
                success: false,
                message: "You are not a member of this group."
            });
        }

        const adminIds = [...getAdminIds(conversation)];

        if (!adminIds.includes(currentUserId)) {
            return res.status(400).json({
                success: false,
                message: "You are not a group admin."
            });
        }

        if (adminIds.length <= 1) {
            return res.status(400).json({
                success: false,
                message: "Promote another member before resigning as the last admin."
            });
        }

        const remainingAdmins = adminIds.filter(
            (id) => id !== currentUserId
        );

        setGroupAdmins(conversation, remainingAdmins);

        await conversation.save();

        const io = getIO(req);

        await persistGroupSystemEvent({
            io,
            conversationId,
            actorId: req.user._id,
            type: "admin_changed",
            previousAdminId: currentUserId,
            newAdminId: remainingAdmins[0]
        });

        const updatedConversation = await populateConversation(
            conversation._id
        );

        io?.to(`conversation:${conversationId}`).emit(
            "group_admin_changed",
            {
                conversationId,
                groupAdmins: remainingAdmins,
                conversation: updatedConversation
            }
        );

        return res.status(200).json({
            success: true,
            message: "You have resigned as group admin.",
            conversation: updatedConversation
        });

    } catch (error) {
        console.error("Resign group admin error:", error);

        return res.status(500).json({
            success: false,
            message: "Failed to resign as group admin."
        });
    }
};

// ======================================================
// DELETE GROUP FOR EVERYONE
// ======================================================

export const deleteGroup = async (req, res) => {
    try {
        const { conversationId } = req.params;

        if (!validateConversationId(conversationId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid group ID."
            });
        }

        const conversation = await Conversation.findById(conversationId);

        if (!conversation) {
            return res.status(404).json({
                success: false,
                message: "Group not found."
            });
        }

        if (conversation.conversationType !== "group") {
            return res.status(400).json({
                success: false,
                message: "Only groups can be deleted using this operation."
            });
        }

        normalizeGroupAdmins(conversation);

        if (!isParticipant(conversation, req.user._id)) {
            return res.status(403).json({
                success: false,
                message: "You are not a group member."
            });
        }

        if (!isAdmin(conversation, req.user._id)) {
            return res.status(403).json({
                success: false,
                message: "Only group admins can delete this group."
            });
        }

        const memberIds = conversation.participants.map(getId);

        const attachments = await EncryptedAttachment.find({
            conversationId: conversation._id
        }).select("storageName");

        const uploadDirectory = path.resolve(
            process.cwd(),
            "uploads",
            "encrypted"
        );

        await EncryptedAttachment.deleteMany({
            conversationId: conversation._id
        });

        await Message.deleteMany({
            conversationId: conversation._id
        });

        // Remove the group-key state as part of group deletion.
        await GroupKeyState.deleteOne({
            conversationId: conversation._id
        });

        await Conversation.findByIdAndDelete(conversation._id);

        for (const attachment of attachments) {
            const storageName = attachment.storageName;

            if (
                !storageName ||
                path.basename(storageName) !== storageName
            ) {
                console.error(
                    "Skipped invalid attachment storage name:",
                    storageName
                );
                continue;
            }

            const filePath = path.resolve(
                uploadDirectory,
                storageName
            );

            if (!filePath.startsWith(uploadDirectory + path.sep)) {
                console.error(
                    "Skipped unsafe attachment path:",
                    storageName
                );
                continue;
            }

            try {
                await fs.unlink(filePath);
            } catch (fileError) {
                if (fileError.code !== "ENOENT") {
                    console.error(
                        "ENCRYPTED FILE CLEANUP ERROR:",
                        fileError
                    );
                }
            }
        }

        const io = getIO(req);

        emitConversationRemoved(
            io,
            memberIds,
            conversationId
        );

        io?.to(`conversation:${conversationId}`).emit(
            "group_deleted",
            {
                conversationId: String(conversationId)
            }
        );

        return res.status(200).json({
            success: true,
            message: "Group deleted successfully for everyone."
        });

    } catch (error) {
        console.error("DELETE GROUP ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to delete the group. Please try again."
        });
    }
};