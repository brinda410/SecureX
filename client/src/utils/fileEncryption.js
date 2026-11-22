// ==========================================
// SECUREX FILE ENCRYPTION
// AES-256-GCM
// Strict File Validation + Magic Byte Checks
// ==========================================

const MAX_FILE_SIZE = 25 * 1024 * 1024;

// ==========================================
// ALLOWED FILE TYPES
// ==========================================

const EXTENSION_TYPES = {
    // Documents
    pdf: "application/pdf",
    doc: "application/msword",
    docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    xls: "application/vnd.ms-excel",
    xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ppt: "application/vnd.ms-powerpoint",
    pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    txt: "text/plain",
    csv: "text/csv",

    // Images
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    png: "image/png",
    gif: "image/gif",
    webp: "image/webp",

    // Audio
    mp3: "audio/mpeg",
    wav: "audio/wav",
    ogg: "audio/ogg",
    webm: "audio/webm",
    m4a: "audio/mp4",

    // Video
    mp4: "video/mp4",
    mov: "video/quicktime",
    avi: "video/x-msvideo",
};

const MIME_ALIASES = {
    "audio/mp3": "audio/mpeg",
    "audio/x-wav": "audio/wav",
    "audio/wave": "audio/wav",
    "audio/x-m4a": "audio/mp4",
    "application/x-pdf": "application/pdf",
};

const ALLOWED_TYPES = new Set([
    ...Object.values(EXTENSION_TYPES),
    "video/webm",
]);

// ==========================================
// BASIC HELPERS
// ==========================================

const generateIV = () =>
    window.crypto.getRandomValues(new Uint8Array(12));

const toBase64 = (buffer) => {
    const bytes = new Uint8Array(buffer);
    let binary = "";

    const chunkSize = 0x8000;

    for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode(
            ...bytes.subarray(i, i + chunkSize)
        );
    }

    return window.btoa(binary);
};

const fromBase64 = (value) => {
    if (typeof value !== "string" || !value.trim()) {
        throw new Error("Invalid encryption data.");
    }

    const normalized = value.trim();

    if (
        normalized.length % 4 !== 0 ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(normalized)
    ) {
        throw new Error("Invalid Base64 encryption data.");
    }

    const binary = window.atob(normalized);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
};

const getExtension = (filename) => {
    if (typeof filename !== "string") {
        return "";
    }

    const name = filename.split(/[\\/]/).pop();
    const index = name.lastIndexOf(".");

    if (index <= 0 || index === name.length - 1) {
        return "";
    }

    return name.substring(index + 1).toLowerCase();
};

const getFileMimeType = (file) => {
    const extension = getExtension(file.name);
    return EXTENSION_TYPES[extension] || "";
};

// ==========================================
// MIME VALIDATION
// ==========================================

const validateMimeType = (file, expectedMime) => {
    const suppliedMime = (file.type || "")
        .split(";")[0]
        .toLowerCase()
        .trim();

    // Browsers may omit MIME information.
    // Extension and signature checks still apply.
    if (!suppliedMime) {
        return;
    }

    const normalizedMime =
        MIME_ALIASES[suppliedMime] || suppliedMime;

    if (
        !ALLOWED_TYPES.has(normalizedMime) ||
        normalizedMime !== expectedMime
    ) {
        throw new Error(
            "The file extension and MIME type do not match."
        );
    }
};

// ==========================================
// FILE SIGNATURE VALIDATION
// ==========================================

const startsWithBytes = (bytes, signature, offset = 0) => {
    if (bytes.length < offset + signature.length) {
        return false;
    }

    return signature.every(
        (value, index) => bytes[offset + index] === value
    );
};

const readAscii = (bytes, start, length) => {
    return String.fromCharCode(
        ...bytes.subarray(start, start + length)
    );
};

const validateFileSignature = (extension, bytes) => {
    const signatures = {
        pdf: () =>
            startsWithBytes(bytes, [
                0x25, 0x50, 0x44, 0x46, 0x2D
            ]),

        jpg: () =>
            startsWithBytes(bytes, [0xFF, 0xD8, 0xFF]),

        jpeg: () =>
            startsWithBytes(bytes, [0xFF, 0xD8, 0xFF]),

        png: () =>
            startsWithBytes(bytes, [
                0x89, 0x50, 0x4E, 0x47,
                0x0D, 0x0A, 0x1A, 0x0A
            ]),

        gif: () =>
            ["GIF87a", "GIF89a"].includes(
                readAscii(bytes, 0, 6)
            ),

        webp: () =>
            readAscii(bytes, 0, 4) === "RIFF" &&
            readAscii(bytes, 8, 4) === "WEBP",

        doc: () =>
            startsWithBytes(bytes, [
                0xD0, 0xCF, 0x11, 0xE0,
                0xA1, 0xB1, 0x1A, 0xE1
            ]),

        xls: () =>
            startsWithBytes(bytes, [
                0xD0, 0xCF, 0x11, 0xE0,
                0xA1, 0xB1, 0x1A, 0xE1
            ]),

        ppt: () =>
            startsWithBytes(bytes, [
                0xD0, 0xCF, 0x11, 0xE0,
                0xA1, 0xB1, 0x1A, 0xE1
            ]),

        docx: () =>
            startsWithBytes(bytes, [0x50, 0x4B, 0x03, 0x04]),

        xlsx: () =>
            startsWithBytes(bytes, [0x50, 0x4B, 0x03, 0x04]),

        pptx: () =>
            startsWithBytes(bytes, [0x50, 0x4B, 0x03, 0x04]),

        mp3: () =>
            readAscii(bytes, 0, 3) === "ID3" ||
            (
                bytes.length >= 2 &&
                bytes[0] === 0xFF &&
                (bytes[1] & 0xE0) === 0xE0
            ),

        wav: () =>
            readAscii(bytes, 0, 4) === "RIFF" &&
            readAscii(bytes, 8, 4) === "WAVE",

        ogg: () =>
            readAscii(bytes, 0, 4) === "OggS",

        webm: () =>
            startsWithBytes(bytes, [
                0x1A, 0x45, 0xDF, 0xA3
            ]),

        mp4: () =>
            readAscii(bytes, 4, 4) === "ftyp",

        m4a: () =>
            readAscii(bytes, 4, 4) === "ftyp",

        mov: () =>
            readAscii(bytes, 4, 4) === "ftyp",

        avi: () =>
            readAscii(bytes, 0, 4) === "RIFF" &&
            readAscii(bytes, 8, 4) === "AVI ",
    };

    const validator = signatures[extension];

    // Plain text does not have a fixed magic signature.
    if (extension === "txt" || extension === "csv") {
        if (bytes.includes(0)) {
            throw new Error(
                "The selected text file contains binary data."
            );
        }

        try {
            new TextDecoder("utf-8", {
                fatal: true
            }).decode(bytes);
        } catch {
            throw new Error(
                "The selected text file is not valid UTF-8."
            );
        }

        return;
    }

    if (!validator || !validator()) {
        throw new Error(
            "The file contents do not match the selected file type."
        );
    }
};

// ==========================================
// COMPLETE FILE VALIDATION
// ==========================================

const validateFile = async (file) => {
    if (!(file instanceof File)) {
        throw new Error("Please select a valid file.");
    }

    if (file.size === 0) {
        throw new Error("This file is empty.");
    }

    if (file.size > MAX_FILE_SIZE) {
        throw new Error("Maximum attachment size is 25 MB.");
    }

    const extension = getExtension(file.name);

    if (!extension || !EXTENSION_TYPES[extension]) {
        throw new Error(
            "This file type is not supported by SecureX."
        );
    }

    const suppliedMime = (file.type || "")
        .split(";")[0]
        .toLowerCase()
        .trim();

    // WebM supports both audio and video.
    // Preserve the actual browser-provided media type.
    const expectedMime =
        extension === "webm" &&
        ["audio/webm", "video/webm"].includes(suppliedMime)
            ? suppliedMime
            : EXTENSION_TYPES[extension];

    validateMimeType(file, expectedMime);

    const header = new Uint8Array(
        await file.slice(0, 32).arrayBuffer()
    );

    validateFileSignature(extension, header);

    return expectedMime;
};

// ==========================================
// AES-256 KEY GENERATION
// ==========================================

export const generateFileEncryptionKey = async () => {
    return window.crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256,
        },
        true,
        ["encrypt", "decrypt"]
    );
};

// ==========================================
// EXPORT AES KEY
// ==========================================

export const exportFileEncryptionKey = async (key) => {
    if (!key) {
        throw new Error("File encryption key is missing.");
    }

    const rawKey = await window.crypto.subtle.exportKey(
        "raw",
        key
    );

    return toBase64(rawKey);
};

// ==========================================
// IMPORT AES KEY
// ==========================================

export const importFileEncryptionKey = async (encodedKey) => {
    if (!encodedKey) {
        throw new Error("Encrypted file key is missing.");
    }

    const rawKey = fromBase64(encodedKey);

    if (rawKey.length !== 32) {
        throw new Error("Invalid AES-256 file key.");
    }

    return window.crypto.subtle.importKey(
        "raw",
        rawKey,
        {
            name: "AES-GCM",
            length: 256,
        },
        false,
        ["encrypt", "decrypt"]
    );
};

// ==========================================
// ENCRYPT FILE
// ==========================================

export const encryptFile = async (file, existingKey = null) => {
    try {
        // Validate original file BEFORE encryption.
        const mimeType = await validateFile(file);

        const fileKey =
            existingKey || await generateFileEncryptionKey();

        if (
            fileKey.algorithm?.name !== "AES-GCM" ||
            fileKey.algorithm?.length !== 256 ||
            !fileKey.usages.includes("encrypt") ||
            !fileKey.usages.includes("decrypt")
        ) {
            throw new Error(
                "Invalid AES-256-GCM encryption key."
            );
        }

        const fileBytes = await file.arrayBuffer();

        const fileIV = generateIV();

        const encryptedFile = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: fileIV,
                tagLength: 128,
            },
            fileKey,
            fileBytes
        );

        // Encrypt metadata separately.
        const metadata = JSON.stringify({
            name: file.name,
            type: mimeType,
            size: file.size,
            lastModified: file.lastModified,
        });

        const metadataIV = generateIV();

        const encryptedMetadata =
            await window.crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: metadataIV,
                    tagLength: 128,
                },
                fileKey,
                new TextEncoder().encode(metadata)
            );

        const exportedKey =
            await exportFileEncryptionKey(fileKey);

        return {
            encryptedBlob: new Blob(
                [encryptedFile],
                {
                    type: "application/octet-stream",
                }
            ),

            encryptedMetadata: toBase64(encryptedMetadata),

            fileIV: toBase64(fileIV),

            metadataIV: toBase64(metadataIV),

            fileKey: exportedKey,

            algorithm: "AES-256-GCM",
        };

    } catch (error) {
        console.error("FILE ENCRYPTION FAILED:", error);

        throw new Error(
            error.message ||
            "Unable to encrypt this attachment."
        );
    }
};

// ==========================================
// DECRYPT FILE
// ==========================================

export const decryptFile = async ({
    encryptedBlob,
    encryptedMetadata,
    fileIV,
    metadataIV,
    fileKey,
}) => {
    try {
        if (
            !encryptedBlob ||
            !encryptedMetadata ||
            !fileIV ||
            !metadataIV ||
            !fileKey
        ) {
            throw new Error(
                "Incomplete encrypted attachment data."
            );
        }

        const key =
            await importFileEncryptionKey(fileKey);

        const encryptedBytes =
            await encryptedBlob.arrayBuffer();

        const decryptedBytes =
            await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: fromBase64(fileIV),
                    tagLength: 128,
                },
                key,
                encryptedBytes
            );

        const decryptedMetadata =
            await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: fromBase64(metadataIV),
                    tagLength: 128,
                },
                key,
                fromBase64(encryptedMetadata)
            );

        const metadata = JSON.parse(
            new TextDecoder().decode(decryptedMetadata)
        );

        if (
            !metadata ||
            typeof metadata.name !== "string" ||
            typeof metadata.type !== "string" ||
            !Number.isSafeInteger(metadata.size) ||
            metadata.size <= 0 ||
            metadata.size > MAX_FILE_SIZE ||
            metadata.size !== decryptedBytes.byteLength
        ) {
            throw new Error(
                "Decrypted attachment metadata is invalid."
            );
        }

        const file = new File(
            [decryptedBytes],
            metadata.name,
            {
                type: metadata.type,
                lastModified:
                    metadata.lastModified || Date.now(),
            }
        );

        // Validate decrypted content again.
        await validateFile(file);

        return {
            file,
            metadata,
            objectURL: URL.createObjectURL(file),
        };

    } catch (error) {
        console.error("FILE DECRYPTION FAILED:", error);

        throw new Error(
            "Unable to decrypt or validate this attachment. The file may be corrupted, unsupported, or the key may be incorrect."
        );
    }
};

// ==========================================
// REVOKE DECRYPTED FILE URL
// ==========================================

export const revokeDecryptedFileURL = (objectURL) => {
    if (objectURL) {
        URL.revokeObjectURL(objectURL);
    }
};

// ==========================================
// ATTACHMENT CATEGORY
// ==========================================

export const getAttachmentCategory = (mimeType = "") => {
    const type = mimeType.toLowerCase().trim();

    if (type.startsWith("image/")) return "image";

    if (type.startsWith("video/")) return "video";

    if (type.startsWith("audio/")) return "audio";

    if (
        type === "application/pdf" ||
        type.includes("document") ||
        type.includes("word") ||
        type.includes("spreadsheet") ||
        type.includes("presentation") ||
        type.startsWith("text/")
    ) {
        return "document";
    }

    return "file";
};
