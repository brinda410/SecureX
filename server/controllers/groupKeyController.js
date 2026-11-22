import mongoose from "mongoose";
import Conversation from "../models/Conversation.js";
import GroupKeyState from "../models/GroupKeyState.js";

/* =========================================
   HELPER FUNCTIONS
========================================= */

const getId = (value) => String(value?._id || value || "");

const getMembers = (conversation) => {
    return [
        ...new Set(
            (conversation.participants || [])
                .map(getId)
                .filter(Boolean)
        )
    ].sort();
};

const isGroup = (conversation) => {
    return conversation.conversationType === "group";
};

const isAdmin = (conversation, userId) => {
    const id = getId(userId);

    return (
        getId(conversation.createdBy) === id ||
        getId(conversation.groupAdmin) === id ||
        (conversation.groupAdmins || []).some(
            (admin) => getId(admin) === id
        )
    );
};

/*
 * Verify that saved member IDs exactly match
 * the current conversation membership.
 */
const hasSameMembers = (state, members) => {
    const savedMembers = (state.memberIds || [])
        .map(getId)
        .sort();

    return (
        JSON.stringify(savedMembers) ===
        JSON.stringify(members)
    );
};

/*
 * Every current member must have exactly one
 * valid encrypted key envelope.
 */
const hasValidEnvelopes = (state, members) => {
    if (!Array.isArray(state.envelopes)) {
        return false;
    }

    const envelopeIds = state.envelopes.map(
        (entry) => getId(entry.userId)
    );

    if (envelopeIds.length !== members.length) {
        return false;
    }

    if (new Set(envelopeIds).size !== members.length) {
        return false;
    }

    return members.every((memberId) => {
        const envelope = state.envelopes.find(
            (entry) => getId(entry.userId) === memberId
        );

        return (
            envelope &&
            typeof envelope.encryptedKey === "string" &&
            envelope.encryptedKey.length >= 16 &&
            envelope.encryptedKey.length <= 12000
        );
    });
};

/*
 * Invalidate stale group keys whenever membership
 * or envelope consistency fails.
 */
const invalidateGroupKeyState = async (state) => {
    state.rotationRequired = true;
    state.envelopes = [];

    await state.save();
};

/*
 * Validate conversation access and group type.
 */
const getConversation = async (conversationId, userId) => {
    if (!mongoose.isValidObjectId(conversationId)) {
        return {
            error: "Invalid conversation ID",
            status: 400
        };
    }

    const conversation = await Conversation.findById(
        conversationId
    );

    if (!conversation) {
        return {
            error: "Conversation not found",
            status: 404
        };
    }

    const members = getMembers(conversation);

    if (!members.includes(getId(userId))) {
        return {
            error: "Access denied",
            status: 403
        };
    }

    if (!isGroup(conversation)) {
        return {
            error: "This operation requires a group conversation",
            status: 400
        };
    }

    return {
        conversation,
        members
    };
};

/* =========================================
   GET GROUP KEY STATE

   GET /api/group-keys/:conversationId
========================================= */

export const getGroupKeyState = async (req, res) => {
    try {
        const result = await getConversation(
            req.params.conversationId,
            req.user._id
        );

        if (result.error) {
            return res.status(result.status).json({
                success: false,
                message: result.error
            });
        }

        const { conversation, members } = result;

        let state = await GroupKeyState.findOne({
            conversationId: conversation._id
        });

        if (!state) {
            return res.json({
                success: true,
                epoch: 0,
                rotationRequired: true,
                members,
                envelopeAvailable: false
            });
        }

        const membershipValid = hasSameMembers(
            state,
            members
        );

        const envelopesValid = hasValidEnvelopes(
            state,
            members
        );

        if (!membershipValid || !envelopesValid) {
            await invalidateGroupKeyState(state);

            return res.json({
                success: true,
                epoch: state.epoch,
                rotationRequired: true,
                members,
                envelopeAvailable: false
            });
        }

        const envelopeAvailable = state.envelopes.some(
            (entry) =>
                getId(entry.userId) === getId(req.user._id)
        );

        return res.json({
            success: true,
            epoch: state.epoch,
            rotationRequired: Boolean(state.rotationRequired),
            members,
            envelopeAvailable: (
                envelopeAvailable &&
                !state.rotationRequired
            )
        });

    } catch (error) {
        console.error("Group key state error:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to retrieve group key state"
        });
    }
};

/* =========================================
   ROTATE GROUP KEY

   POST /api/group-keys/:conversationId/rotate
========================================= */

export const rotateGroupKey = async (req, res) => {
    try {
        const result = await getConversation(
            req.params.conversationId,
            req.user._id
        );

        if (result.error) {
            return res.status(result.status).json({
                success: false,
                message: result.error
            });
        }

        const { conversation, members } = result;

        // Only administrators can rotate group keys.
        if (!isAdmin(conversation, req.user._id)) {
            return res.status(403).json({
                success: false,
                message: "Only group administrators can rotate group keys"
            });
        }

        if (members.length < 2) {
            return res.status(400).json({
                success: false,
                message: "A group must have at least two members"
            });
        }

        const { epoch, envelopes } = req.body || {};

        if (!Number.isSafeInteger(epoch) || epoch < 1) {
            return res.status(400).json({
                success: false,
                message: "A valid key epoch is required"
            });
        }

        if (
            !Array.isArray(envelopes) ||
            envelopes.length !== members.length
        ) {
            return res.status(400).json({
                success: false,
                message: "An encrypted key envelope is required for every current member"
            });
        }

        // Normalize and validate submitted envelopes.
        const normalized = envelopes.map((entry) => ({
            userId: getId(entry?.userId),
            encryptedKey: entry?.encryptedKey
        }));

        const envelopeIds = normalized.map(
            (entry) => entry.userId
        );

        const invalidEnvelope = normalized.some((entry) => (
            !mongoose.isValidObjectId(entry.userId) ||
            typeof entry.encryptedKey !== "string" ||
            entry.encryptedKey.length < 16 ||
            entry.encryptedKey.length > 12000
        ));

        const duplicateEnvelopeIds =
            new Set(envelopeIds).size !== members.length;

        const missingMemberEnvelope = members.some(
            (memberId) => !envelopeIds.includes(memberId)
        );

        if (
            invalidEnvelope ||
            duplicateEnvelopeIds ||
            missingMemberEnvelope
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid, missing, or duplicated member key envelopes"
            });
        }

        let state = await GroupKeyState.findOne({
            conversationId: conversation._id
        });

        const currentEpoch = state?.epoch || 0;
        const expectedEpoch = currentEpoch + 1;

        if (epoch !== expectedEpoch) {
            return res.status(409).json({
                success: false,
                message: `Expected key epoch ${expectedEpoch}`
            });
        }

        if (!state) {
            state = new GroupKeyState({
                conversationId: conversation._id
            });
        }

        // Store the new epoch and encrypted envelopes.
        state.epoch = epoch;
        state.memberIds = members;
        state.envelopes = normalized;
        state.rotationRequired = false;
        state.rotatedBy = req.user._id;
        state.rotatedAt = new Date();

        await state.save();

        return res.json({
            success: true,
            message: "Group key rotation recorded",
            epoch: state.epoch,
            memberCount: members.length
        });

    } catch (error) {
        console.error("Group key rotation error:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to rotate group key"
        });
    }
};

/* =========================================
   GET MY GROUP KEY ENVELOPE

   GET /api/group-keys/:conversationId/my-envelope
========================================= */

export const getMyGroupKeyEnvelope = async (req, res) => {
    try {
        const result = await getConversation(
            req.params.conversationId,
            req.user._id
        );

        if (result.error) {
            return res.status(result.status).json({
                success: false,
                message: result.error
            });
        }

        const { conversation, members } = result;

        const state = await GroupKeyState.findOne({
            conversationId: conversation._id
        });

        if (!state) {
            return res.status(409).json({
                success: false,
                message: "Group key rotation is required"
            });
        }

        // Independently verify current membership.
        const membershipValid = hasSameMembers(
            state,
            members
        );

        // Verify that every current member has one valid envelope.
        const envelopesValid = hasValidEnvelopes(
            state,
            members
        );

        if (!membershipValid || !envelopesValid) {
            await invalidateGroupKeyState(state);

            return res.status(409).json({
                success: false,
                message: "Group membership or key envelopes changed. Group key rotation is required."
            });
        }

        if (state.rotationRequired) {
            return res.status(409).json({
                success: false,
                message: "Group key rotation is required"
            });
        }

        const envelope = state.envelopes.find(
            (entry) =>
                getId(entry.userId) === getId(req.user._id)
        );

        if (!envelope) {
            return res.status(404).json({
                success: false,
                message: "No encrypted key envelope exists for this member"
            });
        }

        return res.json({
            success: true,
            epoch: state.epoch,
            encryptedKey: envelope.encryptedKey
        });

    } catch (error) {
        console.error("Group envelope error:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to retrieve group key envelope"
        });
    }
};