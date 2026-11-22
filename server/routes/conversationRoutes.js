import express from "express";
import protect from "../middleware/authMiddleware.js";

import {
    createConversation,
    getMyConversations,
    createGroup,
    addGroupMember,
    removeGroupMember,
    leaveGroup,
    transferGroupAdmin,
    dismissGroupAdmin,
    resignGroupAdmin,
    deleteGroup
} from "../controllers/conversationController.js";

const router = express.Router();

router.use(protect);

// CONVERSATIONS
router.get("/", getMyConversations);
router.post("/", createConversation);

// GROUP CREATION
router.post("/group", createGroup);

// GROUP MEMBERS
router.post("/:conversationId/members", addGroupMember);

router.delete(
    "/:conversationId/members/:userId",
    removeGroupMember
);

// LEAVE GROUP
router.delete(
    "/:conversationId/leave",
    leaveGroup
);

// GROUP ADMIN MANAGEMENT
router.patch(
    "/:conversationId/admin",
    transferGroupAdmin
);

router.delete(
    "/:conversationId/admins/:userId",
    dismissGroupAdmin
);

router.delete(
    "/:conversationId/admin/resign",
    resignGroupAdmin
);

// DELETE GROUP
router.delete(
    "/:conversationId",
    deleteGroup
);

export default router;