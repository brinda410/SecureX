import express from "express";

import protect from "../middleware/authMiddleware.js";

import {
    getMyDevices,
    revokeDevice,
    revokeOtherDevices
} from "../controllers/deviceController.js";

const router = express.Router();

router.use(protect);

router.get("/", getMyDevices);

router.delete("/others", revokeOtherDevices);

router.delete("/:deviceId", revokeDevice);

export default router;