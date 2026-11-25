/*
 * SECUREX - PERSISTENT CRYPTOGRAPHIC SESSION MANAGER
 *
 * In-memory session + IndexedDB private-key persistence.
 * Compatible with existing SecureX RSA-OAEP-SHA256 keys.
 */

const DB_NAME = "SecureXSessionDB";
const STORE_NAME = "cryptoKeys";
const KEY_ID = "activePrivateKey";

const createEmptySession = () =>
    Object.freeze({
        token: null,
        privateKey: null,
        userId: null,
        name: null,
        email: null,
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
        return (
            String(
                userId._id ||
                userId.id ||
                userId.userId ||
                ""
            ) || null
        );
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

    if (!privateKey.usages?.includes("unwrapKey")) {
        throw new Error(
            "Private key does not support AES key unwrapping."
        );
    }

    return privateKey;
};

/* =========================================
   OPEN INDEXEDDB
========================================= */

const openDatabase = () =>
    new Promise((resolve, reject) => {
        if (!globalThis.indexedDB) {
            reject(
                new Error("IndexedDB is unavailable in this browser.")
            );
            return;
        }

        const request = indexedDB.open(DB_NAME, 1);

        request.onupgradeneeded = () => {
            const db = request.result;

            if (!db.objectStoreNames.contains(STORE_NAME)) {
                db.createObjectStore(STORE_NAME);
            }
        };

        request.onsuccess = () => {
            resolve(request.result);
        };

        request.onerror = () => {
            reject(
                request.error ||
                new Error("Unable to open SecureX session storage.")
            );
        };

        request.onblocked = () => {
            reject(
                new Error("SecureX session storage is blocked.")
            );
        };
    });

/* =========================================
   PERSIST PRIVATE KEY
========================================= */

export const persistPrivateKey = async (privateKey) => {
    validatePrivateKey(privateKey);

    const db = await openDatabase();

    try {
        await new Promise((resolve, reject) => {
            const transaction = db.transaction(
                STORE_NAME,
                "readwrite"
            );

            transaction.objectStore(STORE_NAME).put(
                privateKey,
                KEY_ID
            );

            transaction.oncomplete = resolve;

            transaction.onerror = () => {
                reject(transaction.error);
            };

            transaction.onabort = () => {
                reject(transaction.error);
            };
        });
    } finally {
        db.close();
    }
};

/* =========================================
   RESTORE PRIVATE KEY
========================================= */

export const restorePrivateKey = async () => {
    const db = await openDatabase();

    try {
        const privateKey = await new Promise(
            (resolve, reject) => {
                const transaction = db.transaction(
                    STORE_NAME,
                    "readonly"
                );

                const request = transaction
                    .objectStore(STORE_NAME)
                    .get(KEY_ID);

                request.onsuccess = () => {
                    resolve(request.result || null);
                };

                request.onerror = () => {
                    reject(request.error);
                };
            }
        );

        if (!privateKey) {
            return null;
        }

        return validatePrivateKey(privateKey);
    } finally {
        db.close();
    }
};

/* =========================================
   REMOVE PERSISTED PRIVATE KEY
========================================= */

export const removePersistedPrivateKey = async () => {
    const db = await openDatabase();

    try {
        await new Promise((resolve, reject) => {
            const transaction = db.transaction(
                STORE_NAME,
                "readwrite"
            );

            transaction.objectStore(STORE_NAME).delete(KEY_ID);

            transaction.oncomplete = resolve;

            transaction.onerror = () => {
                reject(transaction.error);
            };

            transaction.onabort = () => {
                reject(transaction.error);
            };
        });
    } finally {
        db.close();
    }
};

/* =========================================
   SET CRYPTO SESSION
========================================= */

export const setCryptoSession = ({
    token,
    privateKey,
    userId,
    name,
    email,
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
        email: email || null,
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
        throw new Error(
            "Authentication token is missing."
        );
    }

    if (!cryptoSession.userId) {
        throw new Error(
            "Crypto session user ID is missing."
        );
    }

    validatePrivateKey(cryptoSession.privateKey);

    return true;
};