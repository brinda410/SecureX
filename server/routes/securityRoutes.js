import express from "express";

import protect from "../middleware/authMiddleware.js";
import adminMiddleware from "../middleware/adminMiddleware.js";

import {
  getSecurityEvents,
  getSecuritySummary
} from "../controllers/securityController.js";

const router = express.Router();

router.use(protect);
router.use(adminMiddleware);

router.get("/events", getSecurityEvents);
router.get("/summary", getSecuritySummary);

export default router;