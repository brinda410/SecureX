// ==========================================
// SECUREX - PUBLIC KEY FINGERPRINT UTILITY
// ==========================================

export const generateKeyFingerprint = async (publicKeyBase64) => {
    try {
        if (
            typeof publicKeyBase64 !== "string" ||
            !publicKeyBase64.trim()
        ) {
            throw new Error("Public key is required.");
        }

        const base64 = publicKeyBase64.trim();

        // Validate standard Base64 format.
        const base64Pattern =
            /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

        if (!base64Pattern.test(base64)) {
            throw new Error("Invalid Base64 public key.");
        }

        // Decode Base64.
        const binary = atob(base64);

        if (!binary.length) {
            throw new Error("Public key cannot be empty.");
        }

        const keyBytes = new Uint8Array(binary.length);

        for (let i = 0; i < binary.length; i++) {
            keyBytes[i] = binary.charCodeAt(i);
        }

        // Generate SHA-256 fingerprint.
        const hash = await window.crypto.subtle.digest(
            "SHA-256",
            keyBytes
        );

        // Convert hash to hexadecimal.
        const hashArray = Array.from(new Uint8Array(hash));

        return hashArray
            .map(byte => byte.toString(16).padStart(2, "0"))
            .join(":")
            .toUpperCase();

    } catch (error) {
        console.error(
            "Fingerprint generation failed:",
            error.message
        );

        throw new Error(
            "Unable to generate public key fingerprint."
        );
    }
};