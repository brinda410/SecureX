/*
 * SecureX - Cryptography Utility
 * AES-256-GCM + RSA-OAEP-SHA256 + PBKDF2-SHA256
 *
 * Compatible with existing SecureX encrypted message formats.
 */

const AES_ALGORITHM = "AES-GCM";
const RSA_ALGORITHM = "RSA-OAEP";
const RSA_HASH = "SHA-256";
const AES_KEY_LENGTH = 256;
const AES_IV_LENGTH = 12;
const AES_TAG_LENGTH = 128;

/* =========================================
   BASE64 HELPERS
========================================= */

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

const base64ToArrayBuffer = (value) => {
    if (value instanceof Uint8Array) {
        return value;
    }

    if (value instanceof ArrayBuffer) {
        return new Uint8Array(value);
    }

    // Support serialized Node.js Buffer objects.
    if (
        value &&
        typeof value === "object" &&
        value.type === "Buffer" &&
        Array.isArray(value.data)
    ) {
        return new Uint8Array(value.data);
    }

    // Support MongoDB binary serialization.
    if (
        value &&
        typeof value === "object" &&
        value.$binary?.base64
    ) {
        value = value.$binary.base64;
    }

    if (typeof value !== "string" || !value.trim()) {
        throw new Error("Invalid Base64 input.");
    }

    let normalized = value.trim();

    // Support Base64URL.
    normalized = normalized
        .replace(/-/g, "+")
        .replace(/_/g, "/");

    // Restore missing Base64 padding.
    normalized += "=".repeat(
        (4 - (normalized.length % 4)) % 4
    );

    try {
        const binary = atob(normalized);
        const bytes = new Uint8Array(binary.length);

        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }

        return bytes;
    } catch {
        throw new Error("Invalid or corrupted Base64 data.");
    }
};

/* =========================================
   CRYPTO VALIDATION
========================================= */

const ensureCrypto = () => {
    if (
        !globalThis.crypto?.subtle ||
        !globalThis.crypto?.getRandomValues
    ) {
        throw new Error(
            "Web Crypto API is unavailable. Use HTTPS."
        );
    }
};

const validateAESKey = (aesKey) => {
    if (!aesKey || aesKey.type !== "secret") {
        throw new Error("Invalid AES encryption key.");
    }

    if (
        aesKey.algorithm?.name !== AES_ALGORITHM ||
        aesKey.algorithm?.length !== AES_KEY_LENGTH
    ) {
        throw new Error("Expected an AES-256-GCM key.");
    }
};

const validateRSAKey = (key) => {
    if (
        !key ||
        key.algorithm?.name !== RSA_ALGORITHM ||
        key.algorithm?.hash?.name !== RSA_HASH
    ) {
        throw new Error("Expected an RSA-OAEP-SHA256 key.");
    }
};

/* =========================================
   IV GENERATION
========================================= */

const generateIV = () => {
    ensureCrypto();

    return globalThis.crypto.getRandomValues(
        new Uint8Array(AES_IV_LENGTH)
    );
};

/* =========================================
   AES ENCRYPTION
========================================= */

const encryptBytes = async (data, aesKey) => {
    ensureCrypto();
    validateAESKey(aesKey);

    const iv = generateIV();

    const encryptedData = await globalThis.crypto.subtle.encrypt(
        {
            name: AES_ALGORITHM,
            iv,
            tagLength: AES_TAG_LENGTH
        },
        aesKey,
        data
    );

    return {
        ciphertext: encryptedData,
        iv: arrayBufferToBase64(iv)
    };
};

/* =========================================
   AES DECRYPTION
========================================= */

const decryptBytes = async (
    ciphertext,
    ivBase64,
    aesKey
) => {
    ensureCrypto();
    validateAESKey(aesKey);

    const iv = base64ToArrayBuffer(ivBase64);
    const encryptedBytes = base64ToArrayBuffer(ciphertext);

    if (iv.length !== AES_IV_LENGTH) {
        throw new Error(
            `Invalid AES-GCM IV: expected ${AES_IV_LENGTH} bytes, received ${iv.length}.`
        );
    }

    if (encryptedBytes.length < 16) {
        throw new Error(
            "Invalid AES-GCM ciphertext: authentication tag is missing."
        );
    }

    return globalThis.crypto.subtle.decrypt(
        {
            name: AES_ALGORITHM,
            iv,
            tagLength: AES_TAG_LENGTH
        },
        aesKey,
        encryptedBytes
    );
};

/* =========================================
   GENERATE AES-256 KEY
========================================= */

export const generateAESKey = async () => {
    ensureCrypto();

    return globalThis.crypto.subtle.generateKey(
        {
            name: AES_ALGORITHM,
            length: AES_KEY_LENGTH
        },
        true,
        ["encrypt", "decrypt"]
    );
};

/* =========================================
   ENCRYPT MESSAGE
========================================= */

export const encryptMessage = async (message, aesKey) => {
    try {
        if (typeof message !== "string") {
            throw new Error("Message must be a string.");
        }

        validateAESKey(aesKey);

        const messageBytes = new TextEncoder().encode(message);

        const encrypted = await encryptBytes(
            messageBytes,
            aesKey
        );

        return {
            ciphertext: arrayBufferToBase64(
                encrypted.ciphertext
            ),
            iv: encrypted.iv,
            algorithm: "AES-256-GCM"
        };
    } catch (error) {
        console.error("SecureX encryption failed:", error);

        throw new Error(
            `Unable to encrypt message: ${error.message}`
        );
    }
};

/* =========================================
   DECRYPT MESSAGE
========================================= */

export const decryptMessage = async (
    ciphertext,
    iv,
    aesKey
) => {
    try {
        const decryptedData = await decryptBytes(
            ciphertext,
            iv,
            aesKey
        );

        return new TextDecoder("utf-8", {
            fatal: true
        }).decode(decryptedData);

    } catch (error) {
        console.error(
            "SecureX AES-GCM decryption failed:",
            {
                name: error.name,
                message: error.message
            }
        );

        if (error.name === "OperationError") {
            throw new Error(
                "AES-GCM authentication failed. The AES key, IV, or ciphertext does not match."
            );
        }

        throw new Error(
            `Message decryption failed: ${error.message}`
        );
    }
};

/* =========================================
   RSA-OAEP KEY GENERATION
========================================= */

export const generateRSAKeyPair = async () => {
    ensureCrypto();

    return globalThis.crypto.subtle.generateKey(
        {
            name: RSA_ALGORITHM,
            modulusLength: 3072,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: RSA_HASH
        },
        true,
        [
            "wrapKey",
            "unwrapKey",
            "encrypt",
            "decrypt"
        ]
    );
};

/* =========================================
   EXPORT PUBLIC KEY
========================================= */

export const exportPublicKey = async (publicKey) => {
    validateRSAKey(publicKey);

    const exported = await globalThis.crypto.subtle.exportKey(
        "spki",
        publicKey
    );

    return arrayBufferToBase64(exported);
};

/* =========================================
   IMPORT PUBLIC KEY
========================================= */

export const importPublicKey = async (publicKeyBase64) => {
    ensureCrypto();

    const keyData = base64ToArrayBuffer(publicKeyBase64);

    return globalThis.crypto.subtle.importKey(
        "spki",
        keyData,
        {
            name: RSA_ALGORITHM,
            hash: RSA_HASH
        },
        true,
        ["wrapKey", "encrypt"]
    );
};

/* =========================================
   WRAP AES KEY
========================================= */

export const wrapAESKey = async (
    aesKey,
    recipientPublicKey
) => {
    ensureCrypto();

    validateAESKey(aesKey);
    validateRSAKey(recipientPublicKey);

    if (!recipientPublicKey.usages.includes("wrapKey")) {
        throw new Error(
            "RSA public key does not permit AES key wrapping."
        );
    }

    const wrappedKey = await globalThis.crypto.subtle.wrapKey(
        "raw",
        aesKey,
        recipientPublicKey,
        {
            name: RSA_ALGORITHM
        }
    );

    return arrayBufferToBase64(wrappedKey);
};

/* =========================================
   UNWRAP AES KEY
========================================= */

export const unwrapAESKey = async (
    wrappedKeyBase64,
    privateKey
) => {
    try {
        ensureCrypto();

        if (!wrappedKeyBase64 || !privateKey) {
            throw new Error(
                "Missing wrapped AES key or private key."
            );
        }

        validateRSAKey(privateKey);

        if (!privateKey.usages.includes("unwrapKey")) {
            throw new Error(
                "RSA private key does not permit key unwrapping."
            );
        }

        const wrappedKey = base64ToArrayBuffer(
            wrappedKeyBase64
        );

        return await globalThis.crypto.subtle.unwrapKey(
            "raw",
            wrappedKey,
            privateKey,
            {
                name: RSA_ALGORITHM
            },
            {
                name: AES_ALGORITHM,
                length: AES_KEY_LENGTH
            },
            true,
            ["encrypt", "decrypt"]
        );

    } catch (error) {
        console.error(
            "SecureX RSA key unwrapping failed:",
            error
        );

        throw error;
    }
};

/* =========================================
   ENCRYPT FILE FOR MULTIPLE RECIPIENTS
========================================= */

export const encryptFileForRecipients = async (
    file,
    recipientPublicKeys
) => {
    try {
        if (!(file instanceof File)) {
            throw new Error("A valid file is required.");
        }

        if (
            !Array.isArray(recipientPublicKeys) ||
            recipientPublicKeys.length === 0
        ) {
            throw new Error(
                "At least one recipient is required."
            );
        }

        const seenRecipients = new Set();

        for (const recipient of recipientPublicKeys) {
            if (!recipient?.userId || !recipient?.publicKey) {
                throw new Error(
                    "Invalid recipient public key."
                );
            }

            const id = String(recipient.userId).toLowerCase();

            if (seenRecipients.has(id)) {
                throw new Error(
                    "Duplicate recipient detected."
                );
            }

            seenRecipients.add(id);

            validateRSAKey(recipient.publicKey);
        }

        const aesKey = await generateAESKey();

        const originalFileBytes = await file.arrayBuffer();

        const encryptedFile = await encryptBytes(
            originalFileBytes,
            aesKey
        );

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
                {
                    type: "application/octet-stream"
                }
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
        console.error("SecureX file encryption failed:", error);

        throw new Error(
            `Unable to encrypt file: ${error.message}`
        );
    }
};

/* =========================================
   DECRYPT FILE
========================================= */

export const decryptFile = async (
    encryptedData,
    privateKey
) => {
    try {
        if (!encryptedData || !privateKey) {
            throw new Error(
                "Missing encrypted file or private key."
            );
        }

        const {
            encryptedBlob,
            encryptedMetadata,
            fileIv,
            metadataIv,
            wrappedAESKey
        } = encryptedData;

        if (
            !encryptedBlob ||
            !encryptedMetadata ||
            !fileIv ||
            !metadataIv ||
            !wrappedAESKey
        ) {
            throw new Error(
                "Incomplete encrypted attachment data."
            );
        }

        const aesKey = await unwrapAESKey(
            wrappedAESKey,
            privateKey
        );

        const encryptedFileBytes =
            await encryptedBlob.arrayBuffer();

        const decryptedFileBytes = await decryptBytes(
            encryptedFileBytes,
            fileIv,
            aesKey
        );

        const encryptedMetadataBytes =
            base64ToArrayBuffer(encryptedMetadata);

        const decryptedMetadataBytes = await decryptBytes(
            encryptedMetadataBytes,
            metadataIv,
            aesKey
        );

        const metadata = JSON.parse(
            new TextDecoder("utf-8", {
                fatal: true
            }).decode(decryptedMetadataBytes)
        );

        if (
            typeof metadata.name !== "string" ||
            typeof metadata.type !== "string"
        ) {
            throw new Error(
                "Invalid decrypted file metadata."
            );
        }

        const decryptedBlob = new Blob(
            [decryptedFileBytes],
            {
                type: metadata.type ||
                    "application/octet-stream"
            }
        );

        return {
            blob: decryptedBlob,
            fileName: metadata.name,
            mimeType: metadata.type,
            size: metadata.size
        };

    } catch (error) {
        console.error("SecureX file decryption failed:", error);

        throw new Error(
            `Unable to decrypt file: ${error.message}`
        );
    }
};

/* =========================================
   PBKDF2 PASSWORD KEY DERIVATION
========================================= */

const deriveProtectionKey = async (
    password,
    salt
) => {
    ensureCrypto();

    if (
        typeof password !== "string" ||
        !password
    ) {
        throw new Error("A valid password is required.");
    }

    const passwordKey =
        await globalThis.crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(password),
            "PBKDF2",
            false,
            ["deriveKey"]
        );

    return globalThis.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: 600000,
            hash: RSA_HASH
        },
        passwordKey,
        {
            name: AES_ALGORITHM,
            length: AES_KEY_LENGTH
        },
        false,
        ["encrypt", "decrypt"]
    );
};

/* =========================================
   PROTECT PRIVATE KEY
========================================= */

export const protectPrivateKey = async (
    privateKey,
    password
) => {
    ensureCrypto();
    validateRSAKey(privateKey);

    const privateKeyData =
        await globalThis.crypto.subtle.exportKey(
            "pkcs8",
            privateKey
        );

    const salt = globalThis.crypto.getRandomValues(
        new Uint8Array(16)
    );

    const iv = generateIV();

    const protectionKey = await deriveProtectionKey(
        password,
        salt
    );

    const encryptedPrivateKey =
        await globalThis.crypto.subtle.encrypt(
            {
                name: AES_ALGORITHM,
                iv,
                tagLength: AES_TAG_LENGTH
            },
            protectionKey,
            privateKeyData
        );

    return {
        encryptedPrivateKey:
            arrayBufferToBase64(encryptedPrivateKey),

        salt: arrayBufferToBase64(salt),
        iv: arrayBufferToBase64(iv),
        kdf: "PBKDF2-SHA256",
        iterations: 600000
    };
};

/* =========================================
   UNLOCK PRIVATE KEY
========================================= */

export const unlockPrivateKey = async (
    protectedData,
    password
) => {
    try {
        ensureCrypto();

        if (
            !protectedData?.salt ||
            !protectedData?.iv ||
            !protectedData?.encryptedPrivateKey
        ) {
            throw new Error(
                "Incomplete protected private-key data."
            );
        }

        const salt = base64ToArrayBuffer(
            protectedData.salt
        );

        const iv = base64ToArrayBuffer(
            protectedData.iv
        );

        if (salt.length !== 16 || iv.length !== AES_IV_LENGTH) {
            throw new Error(
                "Invalid private-key protection parameters."
            );
        }

        const protectionKey = await deriveProtectionKey(
            password,
            salt
        );

        const decryptedPrivateKey =
            await globalThis.crypto.subtle.decrypt(
                {
                    name: AES_ALGORITHM,
                    iv,
                    tagLength: AES_TAG_LENGTH
                },
                protectionKey,
                base64ToArrayBuffer(
                    protectedData.encryptedPrivateKey
                )
            );

        return globalThis.crypto.subtle.importKey(
            "pkcs8",
            decryptedPrivateKey,
            {
                name: RSA_ALGORITHM,
                hash: RSA_HASH
            },
            true,
            ["unwrapKey", "decrypt"]
        );

    } catch (error) {
        console.error(
            "SecureX private-key unlock failed:",
            error
        );

        throw new Error(
            `Unable to unlock private key: ${error.message}`
        );
    }
};
