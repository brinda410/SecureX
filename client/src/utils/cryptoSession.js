/*
 * SECUREX - CRYPTOGRAPHIC SESSION MANAGER
 */

const createEmptySession = () => Object.freeze({
    token: null,
    privateKey: null,
    userId: null,
    name: null,
    email: null
});

let cryptoSession = createEmptySession();

/* =========================================
    NORMALIZE USER ID
========================================= */

const normalizeUserId = (userId) => {
    if (!userId) return null;

    if (typeof userId.toHexString === "function") {
        return userId.toHexString();
    }

    if (typeof userId === "object") {
        return String(
            userId._id ||
            userId.id ||
            userId.userId ||
            ""
        ) || null;
    }

    return String(userId);
};

/* =========================================
   VALIDATE PRIVATE KEY
========================================= */

const validatePrivateKey = (privateKey) => {
    if (!privateKey) {
        throw new Error("Private key is missing.");
    }

    if (
        privateKey.type !== "private" ||
        privateKey.algorithm?.name !== "RSA-OAEP" ||
        privateKey.algorithm?.hash?.name !== "SHA-256"
    ) {
        throw new Error(
            "Invalid SecureX RSA-OAEP-SHA256 private key."
        );
    }

    if (!privateKey.usages.includes("unwrapKey")) {
        throw new Error(
            "Private key does not support AES key unwrapping."
        );
    }

    return privateKey;
};

/* =========================================
   SET CRYPTO SESSION
========================================= */

export const setCryptoSession = ({
    token,
    privateKey,
    userId,
    name,
    email
} = {}) => {
    const normalizedUserId = normalizeUserId(userId);

    if (privateKey) {
        validatePrivateKey(privateKey);
    }

    cryptoSession = Object.freeze({
        token: token || null,
        privateKey: privateKey || null,
        userId: normalizedUserId,
        name: name || null,
        email: email || null
    });

    return cryptoSession;
};

/* =========================================
   GET CRYPTO SESSION
========================================= */

export const getCryptoSession = () => {
    return cryptoSession;
};

/* =========================================
   CHECK SESSION STATUS
========================================= */

export const isCryptoSessionActive = () => {
    return Boolean(
        cryptoSession.token &&
        cryptoSession.privateKey &&
        cryptoSession.userId
    );
};

/* =========================================
   CLEAR CRYPTO SESSION
========================================= */

export const clearCryptoSession = () => {
    cryptoSession = createEmptySession();
};

/* =========================================
   VALIDATE CURRENT SESSION
========================================= */

export const validateCryptoSession = () => {
    if (!cryptoSession.token) {
        throw new Error("Authentication token is missing.");
    }

    if (!cryptoSession.userId) {
        throw new Error("Crypto session user ID is missing.");
    }

    validatePrivateKey(cryptoSession.privateKey);

    return true;
};
