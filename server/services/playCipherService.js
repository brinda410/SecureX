import PlayCipherEvent from "../models/PlayCipherEvent.js";

const SEVERITY_LEVELS = {
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
    CRITICAL: 4
};

export async function recordThreat({
    type,
    severity = "LOW",
    source = "SYSTEM",
    userId = null,
    ipAddress = "unknown",
    method = "",
    endpoint = "",
    description = "",
    metadata = {}
}) {
    try {
        if (!SEVERITY_LEVELS[severity]) {
            severity = "LOW";
        }

        const event = await PlayCipherEvent.create({
            type,
            severity,
            source,
            userId,
            ipAddress: String(ipAddress).slice(0, 100),
            method: String(method).slice(0, 20),
            endpoint: String(endpoint).slice(0, 500),
            description: String(description).slice(0, 1000),
            metadata
        });

        console.warn("[PLAYCIPHER THREAT DETECTED]", {
            id: event._id,
            type,
            severity,
            source,
            ipAddress,
            timestamp: event.detectedAt
        });

        return event;

    } catch (error) {
        console.error(
            "[PLAYCIPHER LOGGING ERROR]",
            error.message
        );

        return null;
    }
}

export function getThreatSeverity(type) {
    const levels = {
        "NOSQL_INJECTION": "CRITICAL",
        "SUSPICIOUS_REQUEST": "HIGH",
        "AUTH_RATE_LIMIT": "HIGH",
        "API_RATE_LIMIT": "MEDIUM",
        "SOCKET_RATE_LIMIT": "MEDIUM",
        "INVALID_SOCKET_AUTH": "HIGH"
    };

    return levels[type] || "LOW";
}