import mongoose from "mongoose";

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
            trim: true,
            maxlength: 4096
        }
    },
    {
        _id: false
    }
);

const encryptedAttachmentSchema = new mongoose.Schema(
    {
        conversationId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Conversation",
            required: true,
            index: true
        },

        uploadedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true
        },

        storageName: {
            type: String,
            required: true,
            unique: true,
            immutable: true,
            maxlength: 100
        },

        encryptedMetadata: {
            type: String,
            required: true,
            maxlength: 2097152
        },

        fileIv: {
            type: String,
            required: true,
            minlength: 16,
            maxlength: 32
        },

        metadataIv: {
            type: String,
            required: true,
            minlength: 16,
            maxlength: 32
        },

        recipientKeyEnvelopes: {
            type: [recipientKeyEnvelopeSchema],
            required: true,
            validate: {
                validator: function (envelopes) {
                    if (!Array.isArray(envelopes)) {
                        return false;
                    }

                    if (envelopes.length === 0 || envelopes.length > 100) {
                        return false;
                    }

                    const ids = envelopes.map(
                        envelope => String(envelope.userId)
                    );

                    return new Set(ids).size === ids.length;
                },
                message: "Recipient key envelopes must be unique."
            }
        },

        encryptedSize: {
            type: Number,
            required: true,
            min: 1,
            max: 27262976
        },

        algorithm: {
            type: String,
            required: true,
            enum: ["AES-256-GCM"],
            default: "AES-256-GCM"
        }
    },
    {
        timestamps: true,
        strict: true
    }
);

encryptedAttachmentSchema.index({
    conversationId: 1,
    createdAt: -1
});

encryptedAttachmentSchema.index({
    uploadedBy: 1,
    createdAt: -1
});

const EncryptedAttachment = mongoose.model(
    "EncryptedAttachment",
    encryptedAttachmentSchema
);

export default EncryptedAttachment;