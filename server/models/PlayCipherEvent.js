import mongoose from "mongoose";

const playCipherEventSchema = new mongoose.Schema(
    {
        type: {
            type: String,
            required: true,
            index: true
        },

        severity: {
            type: String,
            enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            default: "LOW",
            index: true
        },

        source: {
            type: String,
            enum: ["HTTP", "AUTH", "SOCKET", "SYSTEM"],
            required: true
        },

        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null,
            index: true
        },

        ipAddress: {
            type: String,
            default: "unknown",
            index: true
        },

        method: String,
        endpoint: String,
        description: String,

        metadata: {
            type: mongoose.Schema.Types.Mixed,
            default: {}
        },

        detectedAt: {
            type: Date,
            default: Date.now,
            index: true
        }
    },
    {
        timestamps: true,
        strict: true
    }
);

playCipherEventSchema.index({
    severity: 1,
    detectedAt: -1
});

playCipherEventSchema.index({
    ipAddress: 1,
    detectedAt: -1
});

export default mongoose.model(
    "PlayCipherEvent",
    playCipherEventSchema
);