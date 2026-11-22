// ==========================================
// SECUREX - CRYPTOGRAPHIC SESSION MANAGER
// ==========================================

let cryptoSession = Object.freeze({
    token: null,
    privateKey: null,
    userId: null,
    name: null,
    email: null
});

// ==========================================
// NORMALIZE USER ID
// ==========================================

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

// ==========================================
// SET CRYPTO SESSION
// ==========================================

export const setCryptoSession = ({
    token,
    privateKey,
    userId,
    name,
    email
} = {}) => {

    cryptoSession = Object.freeze({
        token: token || null,
        privateKey: privateKey || null,
        userId: normalizeUserId(userId),
        name: name || null,
        email: email || null
    });
};

// ==========================================
// GET CRYPTO SESSION
// ==========================================

export const getCryptoSession = () => {
    return cryptoSession;
};

// ==========================================
// CHECK SESSION STATUS
// ==========================================

export const isCryptoSessionActive = () => {
    return Boolean(
        cryptoSession.token &&
        cryptoSession.privateKey &&
        cryptoSession.userId
    );
};

// ==========================================
// CLEAR CRYPTO SESSION
// ==========================================

export const clearCryptoSession = () => {

    cryptoSession = Object.freeze({
        token: null,
        privateKey: null,
        userId: null,
        name: null,
        email: null
    });
};