import mongoose from "mongoose";

const readStateSchema = new mongoose.Schema(
    {
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true
        },

        lastReadAt: {
            type: Date,
            default: null
        }
    },
    {
        _id: false
    }
);

const conversationSchema = new mongoose.Schema(
    {
        participants: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: "User",
                required: true
            }
        ],

        conversationType: {
            type: String,
            enum: ["private", "group"],
            default: "private"
        },

        groupName: {
            type: String,
            trim: true,
            maxlength: 100,
            default: null
        },

        // Legacy single-admin field.
        // Kept for compatibility with existing groups.
        groupAdmin: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null
        },

        // Supports multiple group administrators.
        groupAdmins: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: "User"
            }
        ],

        createdBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true
        },

        lastMessageAt: {
            type: Date,
            default: null
        },

        messageCount: {
            type: Number,
            default: 0,
            min: 0
        },

        readStates: {
            type: [readStateSchema],
            default: []
        }
    },
    {
        timestamps: true
    }
);

conversationSchema.index({
    participants: 1,
    lastMessageAt: -1
});

conversationSchema.index({
    updatedAt: -1
});

conversationSchema.index({
    "readStates.userId": 1
});

conversationSchema.index({
    groupAdmins: 1
});

const Conversation = mongoose.model(
    "Conversation",
    conversationSchema
);

export default Conversation;