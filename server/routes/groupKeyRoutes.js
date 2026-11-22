import express from "express";
import protect from "../middleware/authMiddleware.js";

import {
  getGroupKeyState,
  rotateGroupKey,
  getMyGroupKeyEnvelope
} from "../controllers/groupKeyController.js";

const router = express.Router();

router.use(protect);

router.get("/:conversationId", getGroupKeyState);

router.post("/:conversationId/rotate", rotateGroupKey);

router.get("/:conversationId/my-envelope", getMyGroupKeyEnvelope);

export default router;