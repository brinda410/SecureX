import Device from "../models/Device.js";

export const getMyDevices = async (req, res) => {
    try {
        const devices = await Device.find({
            userId: req.user._id,
            revokedAt: null
        })
            .select(
                "deviceId deviceName userAgent ipAddress lastSeen createdAt"
            )
            .sort({ lastSeen: -1 })
            .lean();

        return res.json({
            success: true,
            devices: devices.map((device) => ({
                ...device,
                isCurrentDevice:
                    device.deviceId === req.deviceId
            }))
        });

    } catch (error) {
        console.error("GET DEVICES ERROR:", error.message);

        return res.status(500).json({
            success: false,
            message: "Unable to retrieve devices."
        });
    }
};

export const revokeDevice = async (req, res) => {
    try {
        const { deviceId } = req.params;

        const device = await Device.findOneAndUpdate(
            {
                deviceId,
                userId: req.user._id,
                revokedAt: null
            },
            {
                $set: {
                    revokedAt: new Date()
                }
            },
            { new: true }
        );

        if (!device) {
            return res.status(404).json({
                success: false,
                message: "Active device not found."
            });
        }

        return res.json({
            success: true,
            message: "Device session revoked successfully."
        });

    } catch (error) {
        console.error("REVOKE DEVICE ERROR:", error.message);

        return res.status(500).json({
            success: false,
            message: "Unable to revoke device."
        });
    }
};

export const revokeOtherDevices = async (req, res) => {
    try {
        const result = await Device.updateMany(
            {
                userId: req.user._id,
                deviceId: { $ne: req.deviceId },
                revokedAt: null
            },
            {
                $set: {
                    revokedAt: new Date()
                }
            }
        );

        return res.json({
            success: true,
            revokedCount: result.modifiedCount,
            message: "Other device sessions have been revoked."
        });

    } catch (error) {
        console.error("REVOKE DEVICES ERROR:", error.message);

        return res.status(500).json({
            success: false,
            message: "Unable to revoke other devices."
        });
    }
};