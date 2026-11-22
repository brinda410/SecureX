/*
 * SecureX - Cryptography Utility
 * AES-256-GCM + RSA-OAEP-SHA256 + PBKDF2-SHA256
 *
 * Includes:
 * - Message encryption and decryption
 * - RSA key generation and management
 * - Private-key protection
 * - Encrypted file uploads and downloads
 * - Multi-recipient AES key wrapping
 */

const arrayBufferToBase64 = (buffer) => {
    const bytes = buffer instanceof Uint8Array
        ? buffer
        : new Uint8Array(buffer);

    let binary = "";
    const chunkSize = 0x8000;

    for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode(
            ...bytes.subarray(i, i + chunkSize)
        );
    }

    return btoa(binary);
};

const base64ToArrayBuffer = (base64) => {
    if (typeof base64 !== "string" || !base64) {
        throw new Error("Invalid Base64 input");
    }

    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
};

const generateIV = () => {
    return window.crypto.getRandomValues(new Uint8Array(12));
};

const encryptBytes = async (data, aesKey) => {
    const iv = generateIV();

    const encryptedData = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv,
            tagLength: 128
        },
        aesKey,
        data
    );

    return {
        ciphertext: encryptedData,
        iv: arrayBufferToBase64(iv)
    };
};

const decryptBytes = async (ciphertext, ivBase64, aesKey) => {
    const iv = base64ToArrayBuffer(ivBase64);

    if (iv.length !== 12) {
        throw new Error("Invalid AES-GCM IV. Expected 12 bytes.");
    }

    return window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv,
            tagLength: 128
        },
        aesKey,
        ciphertext
    );
};

/* Generate AES-256-GCM key */

export const generateAESKey = async () => {
    return window.crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256
        },
        true,
        ["encrypt", "decrypt"]
    );
};

/* Encrypt message */

export const encryptMessage = async (message, aesKey) => {
    try {
        const encoder = new TextEncoder();
        const messageBytes = encoder.encode(message);

        const encrypted = await encryptBytes(messageBytes, aesKey);

        return {
            ciphertext: arrayBufferToBase64(encrypted.ciphertext),
            iv: encrypted.iv,
            algorithm: "AES-256-GCM"
        };
    } catch (error) {
        console.error("Encryption failed:", error);
        throw new Error(`Unable to encrypt message: ${error.message}`);
    }
};

/* Decrypt message */

export const decryptMessage = async (ciphertext, iv, aesKey) => {
    try {
        const encryptedBytes = base64ToArrayBuffer(ciphertext);

        const decryptedData = await decryptBytes(
            encryptedBytes,
            iv,
            aesKey
        );

        return new TextDecoder().decode(decryptedData);
    } catch (error) {
        console.error("AES decryption failed:", error);
        throw new Error(`Message decryption failed: ${error.message}`);
    }
};

/* Generate RSA-OAEP key pair */

export const generateRSAKeyPair = async () => {
    return window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 3072,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        },
        true,
        ["wrapKey", "unwrapKey", "encrypt", "decrypt"]
    );
};

/* Export public key */

export const exportPublicKey = async (publicKey) => {
    const exported = await window.crypto.subtle.exportKey(
        "spki",
        publicKey
    );

    return arrayBufferToBase64(exported);
};

/* Import public key */

export const importPublicKey = async (publicKeyBase64) => {
    const keyData = base64ToArrayBuffer(publicKeyBase64);

    return window.crypto.subtle.importKey(
        "spki",
        keyData,
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        true,
        ["wrapKey", "encrypt"]
    );
};

/* Wrap AES key using recipient's RSA public key */

export const wrapAESKey = async (aesKey, recipientPublicKey) => {
    const wrappedKey = await window.crypto.subtle.wrapKey(
        "raw",
        aesKey,
        recipientPublicKey,
        {
            name: "RSA-OAEP"
        }
    );

    return arrayBufferToBase64(wrappedKey);
};

/* Unwrap AES key using recipient's RSA private key */

export const unwrapAESKey = async (wrappedKeyBase64, privateKey) => {
    try {
        if (!wrappedKeyBase64 || !privateKey) {
            throw new Error("Missing wrapped AES key or private key");
        }

        const wrappedKey = base64ToArrayBuffer(wrappedKeyBase64);

        return await window.crypto.subtle.unwrapKey(
            "raw",
            wrappedKey,
            privateKey,
            {
                name: "RSA-OAEP"
            },
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );
    } catch (error) {
        console.error("RSA key unwrapping failed:", error);
        throw error;
    }
};

/*
 * ENCRYPT FILE FOR MULTIPLE RECIPIENTS
 *
 * recipientPublicKeys format:
 *
 * [
 *   {
 *     userId: "user-id",
 *     publicKey: CryptoKey
 *   }
 * ]
 *
 * Every participant receives their own RSA-wrapped AES key.
 */

export const encryptFileForRecipients = async (
    file,
    recipientPublicKeys
) => {
    try {
        if (!(file instanceof File)) {
            throw new Error("A valid file is required");
        }

        if (!Array.isArray(recipientPublicKeys) ||
            recipientPublicKeys.length === 0) {
            throw new Error("At least one recipient is required");
        }

        const seenRecipients = new Set();

        for (const recipient of recipientPublicKeys) {
            if (!recipient?.userId || !recipient?.publicKey) {
                throw new Error("Invalid recipient public key");
            }

            const id = String(recipient.userId);

            if (seenRecipients.has(id)) {
                throw new Error("Duplicate recipient detected");
            }

            seenRecipients.add(id);

            if (recipient.publicKey.algorithm?.name !== "RSA-OAEP") {
                throw new Error("Recipient key must use RSA-OAEP");
            }
        }

        // Generate a unique AES key for this file.
        const aesKey = await generateAESKey();

        // Read the original file into memory.
        const originalFileBytes = await file.arrayBuffer();

        // Encrypt the file bytes.
        const encryptedFile = await encryptBytes(
            originalFileBytes,
            aesKey
        );

        // Encrypt metadata separately using a fresh IV.
        const metadata = {
            name: file.name,
            type: file.type || "application/octet-stream",
            size: file.size,
            lastModified: file.lastModified
        };

        const metadataBytes = new TextEncoder().encode(
            JSON.stringify(metadata)
        );

        const encryptedMetadata = await encryptBytes(
            metadataBytes,
            aesKey
        );

        // Wrap the AES key for every participant.
        const recipientKeyEnvelopes = await Promise.all(
            recipientPublicKeys.map(async (recipient) => ({
                userId: String(recipient.userId),
                wrappedAESKey: await wrapAESKey(
                    aesKey,
                    recipient.publicKey
                )
            }))
        );

        return {
            encryptedBlob: new Blob(
                [encryptedFile.ciphertext],
                { type: "application/octet-stream" }
            ),

            encryptedMetadata: arrayBufferToBase64(
                encryptedMetadata.ciphertext
            ),

            fileIv: encryptedFile.iv,

            metadataIv: encryptedMetadata.iv,

            recipientKeyEnvelopes,

            algorithm: "AES-256-GCM",

            originalSize: file.size
        };
    } catch (error) {
        console.error("File encryption failed:", error);
        throw new Error(`Unable to encrypt file: ${error.message}`);
    }
};

/*
 * DECRYPT DOWNLOADED FILE
 *
 * encryptedData format:
 *
 * {
 *   encryptedBlob: Blob,
 *   encryptedMetadata: string,
 *   fileIv: string,
 *   metadataIv: string,
 *   wrappedAESKey: string
 * }
 */

export const decryptFile = async (
    encryptedData,
    privateKey
) => {
    try {
        if (!encryptedData || !privateKey) {
            throw new Error("Missing encrypted file or private key");
        }

        const {
            encryptedBlob,
            encryptedMetadata,
            fileIv,
            metadataIv,
            wrappedAESKey
        } = encryptedData;

        if (!encryptedBlob ||
            !encryptedMetadata ||
            !fileIv ||
            !metadataIv ||
            !wrappedAESKey) {
            throw new Error("Incomplete encrypted attachment data");
        }

        // Recover the AES key using this recipient's private key.
        const aesKey = await unwrapAESKey(
            wrappedAESKey,
            privateKey
        );

        // Decrypt the file contents.
        const encryptedFileBytes = await encryptedBlob.arrayBuffer();

        const decryptedFileBytes = await decryptBytes(
            encryptedFileBytes,
            fileIv,
            aesKey
        );

        // Decrypt the file metadata.
        const encryptedMetadataBytes = base64ToArrayBuffer(
            encryptedMetadata
        );

        const decryptedMetadataBytes = await decryptBytes(
            encryptedMetadataBytes,
            metadataIv,
            aesKey
        );

        const metadata = JSON.parse(
            new TextDecoder().decode(decryptedMetadataBytes)
        );

        if (
            typeof metadata.name !== "string" ||
            typeof metadata.type !== "string"
        ) {
            throw new Error("Invalid decrypted file metadata");
        }

        const decryptedBlob = new Blob(
            [decryptedFileBytes],
            {
                type: metadata.type || "application/octet-stream"
            }
        );

        return {
            blob: decryptedBlob,
            fileName: metadata.name,
            mimeType: metadata.type,
            size: metadata.size
        };
    } catch (error) {
        console.error("File decryption failed:", error);
        throw new Error(`Unable to decrypt file: ${error.message}`);
    }
};

/* Derive password-based protection key */

const deriveProtectionKey = async (password, salt) => {
    const encoder = new TextEncoder();

    const passwordKey = await window.crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: 600000,
            hash: "SHA-256"
        },
        passwordKey,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
};

/* Protect RSA private key before storage */

export const protectPrivateKey = async (privateKey, password) => {
    const privateKeyData = await window.crypto.subtle.exportKey(
        "pkcs8",
        privateKey
    );

    const salt = window.crypto.getRandomValues(
        new Uint8Array(16)
    );

    const iv = generateIV();

    const protectionKey = await deriveProtectionKey(
        password,
        salt
    );

    const encryptedPrivateKey = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv,
            tagLength: 128
        },
        protectionKey,
        privateKeyData
    );

    return {
        encryptedPrivateKey: arrayBufferToBase64(encryptedPrivateKey),
        salt: arrayBufferToBase64(salt),
        iv: arrayBufferToBase64(iv),
        kdf: "PBKDF2-SHA256",
        iterations: 600000
    };
};

/* Unlock protected RSA private key */

export const unlockPrivateKey = async (protectedData, password) => {
    try {
        const salt = base64ToArrayBuffer(protectedData.salt);
        const iv = base64ToArrayBuffer(protectedData.iv);

        if (salt.length !== 16 || iv.length !== 12) {
            throw new Error("Invalid private-key protection parameters");
        }

        const protectionKey = await deriveProtectionKey(
            password,
            salt
        );

        const decryptedPrivateKey = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv,
                tagLength: 128
            },
            protectionKey,
            base64ToArrayBuffer(protectedData.encryptedPrivateKey)
        );

        return window.crypto.subtle.importKey(
            "pkcs8",
            decryptedPrivateKey,
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            true,
            ["unwrapKey", "decrypt"]
        );
    } catch (error) {
        console.error("Private key unlock failed:", error);
        throw new Error(`Unable to unlock private key: ${error.message}`);
    }
};