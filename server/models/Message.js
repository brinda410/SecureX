import mongoose from "mongoose";

/* =====================================================
    RECIPIENT KEY ENVELOPE
===================================================== */

const recipientKeyEnvelopeSchema = new mongoose.Schema(
    {
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true
        },

        wrappedAESKey: {
            type: String,
            required: true,
            maxlength: 4096
        }
    },
    { _id: false }
);


/* =====================================================
    ENCRYPTED ATTACHMENT
===================================================== */

const attachmentSchema = new mongoose.Schema(
    {
        encryptedFileName: {
            type: String,
            default: null,
            maxlength: 4096
        },

        encryptedMimeType: {
            type: String,
            default: null,
            maxlength: 1024
        },

        encryptedFileSize: {
            type: String,
            default: null,
            maxlength: 512
        },

        storagePath: {
            type: String,
            default: null,
            maxlength: 2048
        },

        fileIv: {
            type: String,
            default: null,
            maxlength: 100
        }
    },
    { _id: false }
);


/* =====================================================
    GROUP SYSTEM EVENT
===================================================== */

const systemEventSchema = new mongoose.Schema(
    {
        type: {
            type: String,
            enum: [
                "group_created",
                "member_added",
                "member_removed",
                "member_left",
                "admin_changed"
            ],
            required: true
        },

        actorId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true
        },

        targetUserId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null
        },

        previousAdminId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null
        },

        newAdminId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null
        }
    },
    { _id: false }
);


/* =====================================================
    MESSAGE SCHEMA
===================================================== */

const messageSchema = new mongoose.Schema(
    {
        /* Conversation */

        conversationId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Conversation",
            required: true,
            index: true
        },

        /* Sender */

        sender: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true
        },


        /* =================================================
          ENCRYPTED MESSAGE CONTENT
        ================================================= */

        ciphertext: {
            type: String,

            required: function () {
                return this.messageType !== "system";
            },

            maxlength: 10000000,
            default: null
        },

        iv: {
            type: String,

            required: function () {
                return this.messageType !== "system";
            },

            maxlength: 100,
            default: null
        },

        wrappedAESKey: {
            type: String,
            maxlength: 4096,
            default: null
        },

        senderWrappedAESKey: {
            type: String,
            maxlength: 4096,
            default: null
        },

        recipientKeyEnvelopes: {
            type: [recipientKeyEnvelopeSchema],
            default: []
        },


        /* =================================================
          ENCRYPTION ALGORITHMS
        ================================================= */

        algorithm: {
            type: String,
            enum: ["AES-256-GCM", null],
            default: function () {
                return this.messageType === "system"
                    ? null
                    : "AES-256-GCM";
            }
        },

        keyEncryptionAlgorithm: {
            type: String,
            enum: ["RSA-OAEP-SHA256", null],
            default: function () {
                return this.messageType === "system"
                    ? null
                    : "RSA-OAEP-SHA256";
            }
        },


        /* =================================================
          MESSAGE IDENTIFICATION
        ================================================= */

        clientMessageId: {
            type: String,
            required: true,
            maxlength: 100,
            trim: true
        },


        /* =================================================
          MESSAGE TYPE
        ================================================= */

        messageType: {
            type: String,

            enum: [
                "text",
                "file",
                "image",
                "audio",
                "video",
                "system"
            ],

            default: "text"
        },


        /* =================================================
          SYSTEM EVENT
        ================================================= */

        systemEvent: {
            type: systemEventSchema,
            default: null,

            required: function () {
                return this.messageType === "system";
            }
        },


        /* =================================================
          ATTACHMENT
        ================================================= */

        attachment: {
            type: attachmentSchema,
            default: null
        },


        /* =================================================
          DELIVERY STATUS
        ================================================= */

        deliveryStatus: {
            type: String,

            enum: [
                "sent",
                "delivered",
                "read"
            ],

            default: "sent"
        },

        deliveredAt: {
            type: Date,
            default: null
        },

        readAt: {
            type: Date,
            default: null
        },


        /* =================================================
          EDITING
        ================================================= */

        isEdited: {
            type: Boolean,
            default: false
        },

        editedAt: {
            type: Date,
            default: null
        },


        /* =================================================
          DELETE FOR ME
        ================================================= */

        deletedFor: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: "User"
            }
        ],


        /* =================================================
          MESSAGE SEQUENCE
        ================================================= */

        sequenceNumber: {
            type: Number,
            default: 0,
            min: 0
        }
    },

    {
        timestamps: true,
        strict: true
    }
);


/* =====================================================
    VALIDATION MIDDLEWARE
===================================================== */

messageSchema.pre("validate", function () {

    if (this.messageType === "system") {

        if (!this.systemEvent) {
            throw new Error(
                "System messages require systemEvent metadata."
            );
        }

        if (!this.systemEvent.actorId) {
            throw new Error(
                "System events require an actor."
            );
        }

        // System messages must never contain encrypted content.

        this.ciphertext = null;
        this.iv = null;

        this.wrappedAESKey = null;
        this.senderWrappedAESKey = null;

        this.recipientKeyEnvelopes = [];

        this.algorithm = null;
        this.keyEncryptionAlgorithm = null;

        this.attachment = null;

    } else {

        if (!this.ciphertext || !this.iv) {
            throw new Error(
                "Encrypted messages require ciphertext and IV."
            );
        }

        if (this.systemEvent) {
            throw new Error(
                "Normal messages cannot contain systemEvent metadata."
            );
        }

        // Keep algorithm metadata consistent.

        this.algorithm = "AES-256-GCM";

        this.keyEncryptionAlgorithm = "RSA-OAEP-SHA256";
    }

});


/* =====================================================
    DATABASE INDEXES
===================================================== */

// Prevent duplicate client message IDs from the same sender.

messageSchema.index(
    {
        conversationId: 1,
        sender: 1,
        clientMessageId: 1
    },
    {
        unique: true,
        name: "unique_sender_message_replay_protection"
    }
);


// Conversation message history.

messageSchema.index({
    conversationId: 1,
    createdAt: -1
});


// User-specific deleted messages.

messageSchema.index({
    conversationId: 1,
    deletedFor: 1
});


// Sender message history.

messageSchema.index({
    sender: 1,
    createdAt: -1
});


// Conversation and sender history.

messageSchema.index({
    conversationId: 1,
    sender: 1,
    createdAt: -1
});


/* =====================================================
    MODEL
===================================================== */

const Message =
    mongoose.models.Message ||
    mongoose.model("Message", messageSchema);

export default Message;