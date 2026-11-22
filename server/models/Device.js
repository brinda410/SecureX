import mongoose from "mongoose";

const deviceSchema = new mongoose.Schema(
    {
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true
        },

        deviceId: {
            type: String,
            required: true,
            unique: true,
            index: true
        },

        deviceName: {
            type: String,
            default: "Unknown device",
            maxlength: 120
        },

        userAgent: {
            type: String,
            default: "",
            maxlength: 500
        },

        ipAddress: {
            type: String,
            default: ""
        },

        lastSeen: {
            type: Date,
            default: Date.now
        },

        revokedAt: {
            type: Date,
            default: null
        }
    },
    {
        timestamps: true
    }
);

deviceSchema.index({
    userId: 1,
    revokedAt: 1,
    lastSeen: -1
});

export default mongoose.models.Device ||
    mongoose.model("Device", deviceSchema);