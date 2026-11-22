import mongoose from "mongoose";
import Conversation from "../models/Conversation.js";
import GroupKeyState from "../models/GroupKeyState.js";

const getId = (value) =>
  String(value?._id || value || "");

const getMembers = (conversation) =>
  [...new Set(
    (conversation.participants || [])
      .map(getId)
      .filter(Boolean)
  )].sort();

const isGroup = (conversation) =>
  conversation.conversationType === "group";

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

const getConversation = async (conversationId, userId) => {
  if (!mongoose.isValidObjectId(conversationId)) {
    return { error: "Invalid conversation ID", status: 400 };
  }

  const conversation = await Conversation.findById(conversationId);

  if (!conversation) {
    return { error: "Conversation not found", status: 404 };
  }

  const members = getMembers(conversation);

  if (!members.includes(getId(userId))) {
    return { error: "Access denied", status: 403 };
  }

  if (!isGroup(conversation)) {
    return { error: "This operation requires a group conversation", status: 400 };
  }

  return { conversation, members };
};

// GET /api/group-keys/:conversationId
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

    const previousMembers = (state?.memberIds || [])
      .map(getId)
      .sort();

    const membershipChanged =
      !state ||
      JSON.stringify(previousMembers) !== JSON.stringify(members);

    if (membershipChanged && state) {
      state.rotationRequired = true;
      state.envelopes = [];
      await state.save();
    }

    return res.json({
      success: true,
      epoch: state?.epoch || 0,
      rotationRequired: !state || membershipChanged ||
        state.rotationRequired,
      members,
      envelopeAvailable: Boolean(
        state?.envelopes?.some(
          (entry) => getId(entry.userId) === getId(req.user._id)
        )
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

// POST /api/group-keys/:conversationId/rotate
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

    if (!isAdmin(conversation, req.user._id)) {
      return res.status(403).json({
        success: false,
        message: "Only group administrators can rotate group keys"
      });
    }

    const { epoch, envelopes } = req.body;

    if (!Number.isSafeInteger(epoch) || epoch < 1) {
      return res.status(400).json({
        success: false,
        message: "A valid key epoch is required"
      });
    }

    if (!Array.isArray(envelopes) || envelopes.length !== members.length) {
      return res.status(400).json({
        success: false,
        message: "An encrypted key envelope is required for every current member"
      });
    }

    const normalized = envelopes.map((entry) => ({
      userId: getId(entry.userId),
      encryptedKey: entry.encryptedKey
    }));

    const envelopeIds = normalized.map((entry) => entry.userId);

    if (
      normalized.some(
        (entry) =>
          !mongoose.isValidObjectId(entry.userId) ||
          typeof entry.encryptedKey !== "string" ||
          entry.encryptedKey.length < 16 ||
          entry.encryptedKey.length > 12000
      ) ||
      new Set(envelopeIds).size !== members.length ||
      members.some((memberId) => !envelopeIds.includes(memberId))
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid, missing, or duplicated member key envelopes"
      });
    }

    let state = await GroupKeyState.findOne({
      conversationId: conversation._id
    });

    const expectedEpoch = (state?.epoch || 0) + 1;

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

// GET /api/group-keys/:conversationId/my-envelope
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

    const state = await GroupKeyState.findOne({
      conversationId: result.conversation._id
    });

    if (!state || state.rotationRequired) {
      return res.status(409).json({
        success: false,
        message: "Group key rotation is required"
      });
    }

    const envelope = state.envelopes.find(
      (entry) => getId(entry.userId) === getId(req.user._id)
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