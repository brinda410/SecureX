import mongoose from "mongoose";

const groupKeyStateSchema = new mongoose.Schema(
    {
    conversationId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Conversation",
        required: true,
        unique: true,
        index: true
    },

    epoch: {
        type: Number,
        default: 0,
        min: 0
    },

    memberIds: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
    }],

    envelopes: [{
        userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
        },
        encryptedKey: {
        type: String,
        required: true,
        maxlength: 12000
        }
    }],

    rotationRequired: {
        type: Boolean,
        default: true
    },

    rotatedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        default: null
    },

    rotatedAt: {
        type: Date,
        default: null
    }
    },
    { timestamps: true }
);

export default mongoose.models.GroupKeyState ||
    mongoose.model("GroupKeyState", groupKeyStateSchema);