import fs from "fs/promises";
import path from "path";
import crypto from "crypto";
import mongoose from "mongoose";

import Conversation from "../models/Conversation.js";
import EncryptedAttachment from "../models/EncryptedAttachment.js";

const UPLOAD_DIRECTORY = path.resolve(
    process.cwd(),
    "uploads",
    "encrypted"
);

const MAX_ENCRYPTED_SIZE = 26 * 1024 * 1024;
const MAX_METADATA_SIZE = 1024 * 1024;
const MAX_ENVELOPES = 100;
const MAX_WRAPPED_KEY_SIZE = 4096;

const normalizeId = (id) =>
    String(id || "").toLowerCase();

const getUserId = (req) =>
    String(req.user?._id || req.user?.id || "");

const getParticipantId = (participant) =>
    String(participant?._id || participant?.id || participant || "");

const isValidObjectId = (id) =>
    mongoose.Types.ObjectId.isValid(id);

const isParticipant = (conversation, userId) =>
    conversation.participants.some(
        (participant) =>
            normalizeId(getParticipantId(participant)) ===
            normalizeId(userId)
    );

const isValidBase64 = (value, maximumLength = MAX_ENCRYPTED_SIZE * 2) => {
    if (
        typeof value !== "string" ||
        value.length === 0 ||
        value.length > maximumLength ||
        value.length % 4 !== 0
    ) {
        return false;
    }

    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
        return false;
    }

    return Buffer.from(value, "base64").toString("base64") === value;
};

const getStoragePath = (storageName) => {
    if (
        typeof storageName !== "string" ||
        !/^[a-f0-9-]+\.enc$/i.test(storageName)
    ) {
        throw new Error("Invalid attachment storage name.");
    }

    return path.join(UPLOAD_DIRECTORY, storageName);
};

const validateEnvelopes = (envelopes, participantIds) => {
    if (
        !Array.isArray(envelopes) ||
        envelopes.length === 0 ||
        envelopes.length > MAX_ENVELOPES
    ) {
        return "Invalid recipient key envelopes.";
    }

    if (envelopes.length !== participantIds.length) {
        return "Every conversation member must receive an encrypted file key.";
    }

    const expectedIds = new Set(
        participantIds.map(normalizeId)
    );

    const receivedIds = new Set();

    for (const envelope of envelopes) {
        if (
            !envelope ||
            !isValidObjectId(envelope.userId) ||
            !isValidBase64(
                envelope.wrappedAESKey,
                MAX_WRAPPED_KEY_SIZE
            )
        ) {
            return "Invalid recipient encryption key.";
        }

        const recipientId = normalizeId(envelope.userId);

        if (
            !expectedIds.has(recipientId) ||
            receivedIds.has(recipientId)
        ) {
            return "Invalid or duplicate recipient.";
        }

        receivedIds.add(recipientId);
    }

    if (receivedIds.size !== expectedIds.size) {
        return "A conversation member is missing an encrypted file key.";
    }

    return null;
};

// ======================================================
// UPLOAD ENCRYPTED ATTACHMENT
// ======================================================

export const uploadEncryptedAttachment = async (req, res) => {
    let savedFilePath = null;
    let createdAttachmentId = null;

    try {
        const userId = getUserId(req);

        if (!isValidObjectId(userId)) {
            return res.status(401).json({
                success: false,
                message: "Authentication required."
            });
        }

        if (!req.file?.buffer || req.file.size <= 0) {
            return res.status(400).json({
                success: false,
                message: "Encrypted file is missing."
            });
        }

        if (req.file.size > MAX_ENCRYPTED_SIZE) {
            return res.status(413).json({
                success: false,
                message: "Encrypted attachment exceeds the 26 MB limit."
            });
        }

        const {
            conversationId,
            encryptedMetadata,
            fileIv,
            metadataIv,
            recipientKeyEnvelopes
        } = req.body;

        if (!isValidObjectId(conversationId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid conversation ID."
            });
        }

        if (
            !isValidBase64(encryptedMetadata, MAX_METADATA_SIZE * 2) ||
            !isValidBase64(fileIv, 64) ||
            !isValidBase64(metadataIv, 64)
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid encrypted metadata or initialization vector."
            });
        }

        if (
            Buffer.from(fileIv, "base64").length !== 12 ||
            Buffer.from(metadataIv, "base64").length !== 12
        ) {
            return res.status(400).json({
                success: false,
                message: "AES-GCM requires 12-byte initialization vectors."
            });
        }

        if (
            typeof recipientKeyEnvelopes !== "string" ||
            recipientKeyEnvelopes.length > 600000
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid recipient key envelopes."
            });
        }

        let envelopes;

        try {
            envelopes = JSON.parse(recipientKeyEnvelopes);
        } catch {
            return res.status(400).json({
                success: false,
                message: "Recipient key envelopes must contain valid JSON."
            });
        }

        const conversation = await Conversation.findById(conversationId);

        if (!conversation || !isParticipant(conversation, userId)) {
            return res.status(403).json({
                success: false,
                message: "You are not a member of this conversation."
            });
        }

        const participantIds = conversation.participants.map(
            getParticipantId
        );

        if (
            participantIds.length === 0 ||
            participantIds.some((id) => !isValidObjectId(id)) ||
            new Set(participantIds.map(normalizeId)).size !==
                participantIds.length
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid conversation membership data."
            });
        }

        const envelopeError = validateEnvelopes(
            envelopes,
            participantIds
        );

        if (envelopeError) {
            return res.status(400).json({
                success: false,
                message: envelopeError
            });
        }

        await fs.mkdir(UPLOAD_DIRECTORY, {
            recursive: true
        });

        const storageName = `${crypto.randomUUID()}.enc`;

        savedFilePath = getStoragePath(storageName);

        // Only browser-encrypted bytes are written to disk.
        await fs.writeFile(savedFilePath, req.file.buffer, {
            flag: "wx"
        });

        const attachment = await EncryptedAttachment.create({
            conversationId,
            uploadedBy: userId,
            storageName,
            encryptedMetadata,
            fileIv,
            metadataIv,
            recipientKeyEnvelopes: envelopes.map((envelope) => ({
                userId: envelope.userId,
                wrappedAESKey: envelope.wrappedAESKey
            })),
            encryptedSize: req.file.size,
            algorithm: "AES-256-GCM"
        });

        createdAttachmentId = attachment._id;

        return res.status(201).json({
            success: true,
            message: "Encrypted attachment uploaded successfully.",
            attachment: {
                _id: attachment._id,
                conversationId: attachment.conversationId,
                encryptedMetadata: attachment.encryptedMetadata,
                fileIv: attachment.fileIv,
                metadataIv: attachment.metadataIv,
                encryptedSize: attachment.encryptedSize,
                algorithm: attachment.algorithm,
                createdAt: attachment.createdAt
            }
        });

    } catch (error) {
        // Roll back partial storage if database creation fails.
        if (savedFilePath && !createdAttachmentId) {
            await fs.unlink(savedFilePath).catch(() => {});
        }

        console.error("ENCRYPTED ATTACHMENT UPLOAD ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to upload encrypted attachment."
        });
    }
};

// ======================================================
// DOWNLOAD ENCRYPTED ATTACHMENT
// ======================================================

export const downloadEncryptedAttachment = async (req, res) => {
    try {
        const userId = getUserId(req);
        const { attachmentId } = req.params;

        if (!isValidObjectId(userId)) {
            return res.status(401).json({
                success: false,
                message: "Authentication required."
            });
        }

        if (!isValidObjectId(attachmentId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid attachment ID."
            });
        }

        const attachment = await EncryptedAttachment.findById(
            attachmentId
        );

        if (!attachment) {
            return res.status(404).json({
                success: false,
                message: "Attachment not found."
            });
        }

        const conversation = await Conversation.findById(
            attachment.conversationId
        );

        if (!conversation || !isParticipant(conversation, userId)) {
            return res.status(403).json({
                success: false,
                message: "You cannot access this attachment."
            });
        }

        const userEnvelope = attachment.recipientKeyEnvelopes.find(
            (envelope) =>
                normalizeId(envelope.userId) === normalizeId(userId)
        );

        if (!userEnvelope) {
            return res.status(403).json({
                success: false,
                message: "No encrypted file key is available for your account."
            });
        }

        const filePath = getStoragePath(attachment.storageName);

        const encryptedBuffer = await fs.readFile(filePath);

        if (
            encryptedBuffer.length === 0 ||
            encryptedBuffer.length > MAX_ENCRYPTED_SIZE
        ) {
            return res.status(500).json({
                success: false,
                message: "Stored encrypted attachment is invalid."
            });
        }

        res.set({
            "Cache-Control": "private, no-store",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff"
        });

        return res.status(200).json({
            success: true,
            encryptedFile: encryptedBuffer.toString("base64"),
            encryptedMetadata: attachment.encryptedMetadata,
            fileIv: attachment.fileIv,
            metadataIv: attachment.metadataIv,
            wrappedAESKey: userEnvelope.wrappedAESKey,
            algorithm: attachment.algorithm
        });

    } catch (error) {
        if (error.code === "ENOENT") {
            return res.status(404).json({
                success: false,
                message: "Encrypted file is missing from storage."
            });
        }

        console.error("ENCRYPTED ATTACHMENT DOWNLOAD ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to download encrypted attachment."
        });
    }
};
