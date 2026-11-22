import express from "express";
import multer from "multer";

import protect from "../middleware/authMiddleware.js";

import {
    sendMessage,
    getMessages,
    markConversationRead,
    editMessage,
    deleteMessageForMe,
    deleteMessageForEveryone
} from "../controllers/messageController.js";

import {
    uploadEncryptedAttachment,
    downloadEncryptedAttachment
} from "../controllers/attachmentController.js";

const router = express.Router();


/* Multer configuration */

const upload = multer({
    storage: multer.memoryStorage(),

    limits: {
        fileSize: 26 * 1024 * 1024,
        files: 1,
        fields: 5,
        fieldSize: 2 * 1024 * 1024,
        parts: 6
    }
});


/* All routes require authentication */

router.use(protect);


/* Encrypted attachments */

router.post(
    "/attachments",
    upload.single("file"),
    uploadEncryptedAttachment
);

router.get(
    "/attachments/:attachmentId",
    downloadEncryptedAttachment
);


/* Send message */

router.post(
    "/",
    sendMessage
);


/* Mark conversation as read */

router.patch(
    "/:conversationId/read",
    markConversationRead
);


/* Retrieve messages */

router.get(
    "/:conversationId",
    getMessages
);


/* Edit message */

router.patch(
    "/:messageId",
    editMessage
);


/* Delete for current user */

router.delete(
    "/:messageId/me",
    deleteMessageForMe
);


/* Delete for everyone */

router.delete(
    "/:messageId/everyone",
    deleteMessageForEveryone
);


export default router;