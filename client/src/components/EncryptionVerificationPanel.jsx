import { useState } from "react";

import {
    generateAESKey,
    generateRSAKeyPair,
    encryptMessage,
    decryptMessage,
    wrapAESKey,
    unwrapAESKey,
} from "../utils/crypto.js";

const TEST_MESSAGE = "SECUREX_ENCRYPTION_VERIFICATION_2026";

const initialResults = {
    aes: "WAITING",
    rsa: "WAITING",
    decryption: "WAITING",
    tampering: "WAITING",
};

const styles = {
    card: {
        background: "#0c0a0e",
        border: "1px solid #633044",
        borderRadius: "12px",
        padding: "22px",
        marginTop: "24px",
        color: "#f2eaf0",
    },
    heading: {
        color: "#e4a0b5",
        fontSize: "18px",
        fontWeight: 700,
        marginBottom: "6px",
    },
    description: {
        color: "#a99aa3",
        fontSize: "13px",
        marginBottom: "20px",
    },
    button: {
        background: "#8b1538",
        color: "#fff",
        border: "1px solid #c13b62",
        borderRadius: "7px",
        padding: "11px 18px",
        cursor: "pointer",
        fontWeight: 700,
        marginBottom: "20px",
    },
    row: {
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        padding: "12px 0",
        borderBottom: "1px solid #30202a",
        gap: "12px",
    },
    label: {
        fontSize: "13px",
        color: "#e0d4db",
    },
    output: {
        background: "#08070a",
        border: "1px solid #30202a",
        borderRadius: "8px",
        padding: "14px",
        marginTop: "18px",
        overflowWrap: "anywhere",
        fontSize: "12px",
        lineHeight: 1.7,
    },
};

function Status({ value }) {
    const colors = {
        WAITING: "#92858c",
        RUNNING: "#e5b65c",
        PASS: "#55d69e",
        FAIL: "#ff526b",
    };

    return (
        <span
            style={{
                color: colors[value] || "#92858c",
                fontWeight: 800,
                fontSize: "12px",
            }}
        >
            {value}
        </span>
    );
}

function toBase64(bytes) {
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}

function fromBase64(value) {
    const binary = atob(value);

    return Uint8Array.from(
        binary,
        (character) => character.charCodeAt(0)
    );
}

export default function EncryptionVerificationPanel() {
    const [results, setResults] = useState(initialResults);
    const [running, setRunning] = useState(false);
    const [overall, setOverall] = useState("NOT RUN");
    const [details, setDetails] = useState(null);
    const [error, setError] = useState("");

    const updateResult = (key, value) => {
        setResults((previous) => ({
            ...previous,
            [key]: value,
        }));
    };

    const runVerification = async () => {
        if (running) return;

        setRunning(true);
        setError("");
        setDetails(null);
        setOverall("RUNNING");

        setResults({
            aes: "RUNNING",
            rsa: "WAITING",
            decryption: "WAITING",
            tampering: "WAITING",
        });

        try {
            // TEST 1: AES-256-GCM key generation and encryption.
            const aesKey = await generateAESKey();

            if (
                aesKey.algorithm.name !== "AES-GCM" ||
                aesKey.algorithm.length !== 256
            ) {
                throw new Error("AES-256-GCM key validation failed.");
            }

            const encrypted = await encryptMessage(
                TEST_MESSAGE,
                aesKey
            );

            const aesPassed =
                encrypted.algorithm === "AES-256-GCM" &&
                Boolean(encrypted.ciphertext) &&
                Boolean(encrypted.iv);

            updateResult("aes", aesPassed ? "PASS" : "FAIL");

            if (!aesPassed) {
                throw new Error("AES encryption test failed.");
            }

            // TEST 2: RSA-3072 key generation and AES key wrapping.
            updateResult("rsa", "RUNNING");

            const rsaPair = await generateRSAKeyPair();

            if (
                rsaPair.publicKey.algorithm.modulusLength !== 3072 ||
                rsaPair.publicKey.algorithm.hash.name !== "SHA-256"
            ) {
                throw new Error("RSA-3072/SHA-256 validation failed.");
            }

            const wrappedKey = await wrapAESKey(
                aesKey,
                rsaPair.publicKey
            );

            const recoveredAESKey = await unwrapAESKey(
                wrappedKey,
                rsaPair.privateKey
            );

            const rsaPassed =
                Boolean(wrappedKey) &&
                recoveredAESKey.algorithm.name === "AES-GCM" &&
                recoveredAESKey.algorithm.length === 256;

            updateResult("rsa", rsaPassed ? "PASS" : "FAIL");

            if (!rsaPassed) {
                throw new Error("RSA key wrapping test failed.");
            }

            // TEST 3: Verify normal message decryption.
            updateResult("decryption", "RUNNING");

            const decrypted = await decryptMessage(
                encrypted.ciphertext,
                encrypted.iv,
                recoveredAESKey
            );

            const decryptionPassed = decrypted === TEST_MESSAGE;

            updateResult(
                "decryption",
                decryptionPassed ? "PASS" : "FAIL"
            );

            if (!decryptionPassed) {
                throw new Error("Message decryption verification failed.");
            }

            // TEST 4: Verify that modified ciphertext is rejected.
            updateResult("tampering", "RUNNING");

            const tamperedBytes = fromBase64(
                encrypted.ciphertext
            );

            tamperedBytes[0] ^= 1;

            const tamperedCiphertext = toBase64(tamperedBytes);

            let tamperingPassed = false;

            try {
                await decryptMessage(
                    tamperedCiphertext,
                    encrypted.iv,
                    recoveredAESKey
                );
            } catch (tamperError) {
                // AES-GCM authentication rejection is EXPECTED here.
                // Do not log it as an unexpected application error.
                tamperingPassed = true;
            }

            updateResult(
                "tampering",
                tamperingPassed ? "PASS" : "FAIL"
            );

            if (!tamperingPassed) {
                throw new Error("Tampering detection test failed.");
            }

            setDetails({
                original: TEST_MESSAGE,
                ciphertext: encrypted.ciphertext,
                iv: encrypted.iv,
                encryptionAlgorithm: encrypted.algorithm,
                keyEncryptionAlgorithm: "RSA-OAEP-SHA256",
                rsaKeySize: "3072 bits",
            });

            setOverall("PASS");

        } catch (err) {
            console.error("Encryption verification failed:", err);

            setError(
                err.message || "An encryption verification test failed."
            );

            setOverall("FAIL");

        } finally {
            setRunning(false);
        }
    };

    return (
        <section style={styles.card}>
            <div style={styles.heading}>
                <i className="bi bi-shield-lock-fill"></i>{" "}
                ENCRYPTION VERIFICATION
            </div>

            <p style={styles.description}>
                Live cryptographic verification using SecureX's existing
                Web Crypto encryption functions.
            </p>

            <button
                type="button"
                style={{
                    ...styles.button,
                    opacity: running ? 0.6 : 1,
                }}
                onClick={runVerification}
                disabled={running}
            >
                <i className="bi bi-play-circle"></i>{" "}
                {running ? "RUNNING TESTS..." : "RUN ENCRYPTION TEST"}
            </button>

            {[
                ["AES-256-GCM", results.aes],
                ["RSA-OAEP-SHA256 KEY WRAPPING", results.rsa],
                ["MESSAGE DECRYPTION", results.decryption],
                ["TAMPERING DETECTION", results.tampering],
            ].map(([label, value]) => (
                <div style={styles.row} key={label}>
                    <span style={styles.label}>{label}</span>
                    <Status value={value} />
                </div>
            ))}

            <div style={styles.row}>
                <strong style={styles.label}>OVERALL RESULT</strong>
                <Status value={overall} />
            </div>

            {error && (
                <div
                    style={{
                        ...styles.output,
                        color: "#ff647d",
                    }}
                >
                    Verification error: {error}
                </div>
            )}

            {details && (
                <div style={styles.output}>
                    <div>
                        <strong>Original sample:</strong>
                        <br />
                        {details.original}
                    </div>

                    <br />

                    <div>
                        <strong>Encrypted ciphertext:</strong>
                        <br />
                        {details.ciphertext.slice(0, 120)}
                        {details.ciphertext.length > 120 ? "..." : ""}
                    </div>

                    <br />

                    <div>
                        <strong>IV:</strong> {details.iv}
                    </div>

                    <div>
                        <strong>Encryption:</strong>{" "}
                        {details.encryptionAlgorithm}
                    </div>

                    <div>
                        <strong>Key protection:</strong>{" "}
                        {details.keyEncryptionAlgorithm}
                    </div>

                    <div>
                        <strong>RSA key size:</strong>{" "}
                        {details.rsaKeySize}
                    </div>

                    <br />

                    <div style={{ color: "#55d69e" }}>
                        Cryptographic verification completed.
                    </div>
                </div>
            )}

            <p
                style={{
                    color: "#92858c",
                    fontSize: "11px",
                    marginTop: "16px",
                    marginBottom: 0,
                }}
            >
                This test verifies local cryptographic operations. It does
                not independently verify database storage, deployed transport
                security, or every chat and attachment workflow.
            </p>
        </section>
    );
}