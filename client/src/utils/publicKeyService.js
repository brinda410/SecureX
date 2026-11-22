import { importPublicKey } from "./crypto.js";
import { generateKeyFingerprint } from "./keyFingerprint.js";
import { getCryptoSession } from "./cryptoSession.js";

// ==========================================
// ID NORMALIZATION
// ==========================================

const getId = (value) => {
    if (!value) return "";

    if (typeof value.toHexString === "function") {
        return value.toHexString();
    }

    if (typeof value === "object") {
        return String(
            value._id ||
            value.id ||
            value.userId ||
            ""
        );
    }

    return String(value);
};

// ==========================================
// RETRIEVE ANOTHER USER'S PUBLIC KEY
// ==========================================

export const fetchUserPublicKey = async (userId) => {
    try {
        const session = getCryptoSession();

        if (!session?.token) {
            throw new Error(
                "Please unlock your encryption session first."
            );
        }

        const requestedUserId = getId(userId);

        if (!requestedUserId) {
            throw new Error("User ID is required.");
        }

        const response = await fetch(
            `http://localhost:5000/api/users/${encodeURIComponent(requestedUserId)}/public-key`,
            {
                method: "GET",
                headers: {
                    Authorization: `Bearer ${session.token}`,
                    Accept: "application/json"
                }
            }
        );

        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
            throw new Error(
                data.message || "Unable to retrieve public key."
            );
        }

        if (!data.user?.publicKey) {
            throw new Error(
                "The requested user's public key was not found."
            );
        }

        // Verify returned user identity.
        const returnedUserId = getId(
            data.user.id || data.user._id
        );

        if (
            !returnedUserId ||
            returnedUserId.toLowerCase() !==
            requestedUserId.toLowerCase()
        ) {
            throw new Error(
                "Public key identity verification failed."
            );
        }

        // Validate key version.
        const keyVersion = Number(data.user.keyVersion);

        if (
            !Number.isSafeInteger(keyVersion) ||
            keyVersion < 1
        ) {
            throw new Error(
                "Invalid public key version received."
            );
        }

        // Import public key.
        const publicKey = await importPublicKey(
            data.user.publicKey
        );

        if (
            publicKey.algorithm?.name !== "RSA-OAEP" ||
            publicKey.algorithm?.modulusLength !== 3072
        ) {
            throw new Error(
                "The recipient public key does not meet SecureX key requirements."
            );
        }

        // Generate public key fingerprint.
        const fingerprint = await generateKeyFingerprint(
            data.user.publicKey
        );

        return {
            userId: returnedUserId,
            name: data.user.name,
            publicKey,
            fingerprint,
            keyVersion
        };

    } catch (error) {
        console.error(
            "Public key retrieval failed:",
            error.message
        );

        throw error;
    }
};
