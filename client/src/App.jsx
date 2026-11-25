import { useRef, useState, useEffect } from "react";

import API from "./services/api.js";
import ChatLayout from "./components/ChatLayout.jsx";

import {
    unlockPrivateKey,
    generateRSAKeyPair,
    exportPublicKey,
    protectPrivateKey,
} from "./utils/crypto.js";

import {
    setCryptoSession,
    clearCryptoSession,
    isCryptoSessionActive,
    persistPrivateKey,
    restorePrivateKey,
    removePersistedPrivateKey,
} from "./utils/cryptoSession.js";

import {
    connectSocket,
    disconnectSocket,
} from "./services/socket.js";

// Gmail validation
const GMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@gmail\.com$/i;

// PASSWORD INPUT
function AsteriskPasswordInput({
    value,
    onChange,
    placeholder,
    autoComplete,
    id,
}) {
    const inputRef = useRef(null);

    const handleChange = (event) => {
        const input = event.target;
        const oldPassword = value;
        const oldMasked = "*".repeat(oldPassword.length);
        const newMasked = input.value;

        let prefix = 0;

        while (
            prefix < oldMasked.length &&
            prefix < newMasked.length &&
            oldMasked[prefix] === newMasked[prefix]
        ) {
            prefix++;
        }

        let suffix = 0;

        while (
            suffix < oldPassword.length - prefix &&
            suffix < newMasked.length - prefix &&
            oldMasked[oldPassword.length - 1 - suffix] ===
                newMasked[newMasked.length - 1 - suffix]
        ) {
            suffix++;
        }

        const insertedText = newMasked.slice(
            prefix,
            newMasked.length - suffix
        );

        const updatedPassword =
            oldPassword.slice(0, prefix) +
            insertedText +
            oldPassword.slice(oldPassword.length - suffix);

        onChange(updatedPassword);

        const cursorPosition = prefix + insertedText.length;

        requestAnimationFrame(() => {
            if (inputRef.current) {
                inputRef.current.setSelectionRange(
                    cursorPosition,
                    cursorPosition
                );
            }
        });
    };

    return (
        <input
            ref={inputRef}
            id={id}
            type="text"
            value={"*".repeat(value.length)}
            onChange={handleChange}
            placeholder={placeholder}
            autoComplete={autoComplete}
            spellCheck="false"
            autoCapitalize="off"
            autoCorrect="off"
            inputMode="text"
            className="securex-input securex-password-input"
            aria-label="Password"
        />
    );
}

// MAIN APP
function App() {
    const [isRegister, setIsRegister] = useState(false);
    const [name, setName] = useState("");
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);

    const [token, setToken] = useState(
        () => sessionStorage.getItem("token")
    );

    const [restoreLoading, setRestoreLoading] = useState(
        () => Boolean(sessionStorage.getItem("token"))
    );

    const [cryptoUnlocked, setCryptoUnlocked] = useState(
        () => isCryptoSessionActive()
    );

    const baseURL =
        import.meta.env.VITE_API_URL || "/api";

    // RESET FORM
    const resetForm = () => {
        setName("");
        setEmail("");
        setPassword("");
        setConfirmPassword("");
        setError("");
    };

    // SWITCH LOGIN / REGISTER
    const switchMode = () => {
        setIsRegister((previous) => !previous);
        resetForm();
    };

    /* =========================================
       INITIALIZE SECURE SESSION
    ========================================= */

    const initializeSecureSession = async (
        authToken,
        accountPassword
    ) => {
        const headers = {
            Authorization: `Bearer ${authToken}`,
        };

        let privateKey;

        const keysResponse = await fetch(
            `${baseURL}/users/keys/me`,
            { headers }
        );

        const keysData = await keysResponse
            .json()
            .catch(() => ({}));

        if (keysResponse.ok && keysData.keys) {
            const protectedData = {
                encryptedPrivateKey:
                    keysData.keys.encryptedPrivateKey,
                salt: keysData.keys.salt,
                iv: keysData.keys.iv,
                iterations:
                    keysData.keys.iterations || 600000,
            };

            if (
                !protectedData.encryptedPrivateKey ||
                !protectedData.salt ||
                !protectedData.iv
            ) {
                throw new Error(
                    "Your saved encryption-key data is incomplete."
                );
            }

            try {
                privateKey = await unlockPrivateKey(
                    protectedData,
                    accountPassword
                );
            } catch {
                throw new Error(
                    "Unable to unlock your encryption key. Check your password."
                );
            }
        } else if (
            keysResponse.status === 404 &&
            /encryption keys are not registered/i.test(
                keysData.message || ""
            )
        ) {
            const keyPair = await generateRSAKeyPair();

            const publicKey = await exportPublicKey(
                keyPair.publicKey
            );

            const protectedPrivateKey = await protectPrivateKey(
                keyPair.privateKey,
                accountPassword
            );

            await API.post(
                "/users/keys",
                {
                    publicKey,
                    encryptedPrivateKey:
                        protectedPrivateKey.encryptedPrivateKey,
                    salt: protectedPrivateKey.salt,
                    iv: protectedPrivateKey.iv,
                },
                { headers }
            );

            privateKey = keyPair.privateKey;
        } else {
            const err = new Error(
                keysData.message ||
                    "Unable to retrieve your encryption keys."
            );

            err.status = keysResponse.status;
            throw err;
        }

        const profileResponse = await fetch(
            `${baseURL}/users/me`,
            { headers }
        );

        const profileData = await profileResponse
            .json()
            .catch(() => ({}));

        if (!profileResponse.ok) {
            const err = new Error(
                profileData.message ||
                    "Unable to retrieve account profile."
            );

            err.status = profileResponse.status;
            throw err;
        }

        const currentUser = profileData.user;

        if (!currentUser?._id) {
            throw new Error(
                "User ID was not returned by the server."
            );
        }

        // Set in-memory session
        setCryptoSession({
            token: authToken,
            privateKey,
            userId: currentUser._id,
            name: currentUser.name,
            email: currentUser.email,
        });

        if (!isCryptoSessionActive()) {
            throw new Error(
                "Cryptographic session initialization failed."
            );
        }

        // Persist private CryptoKey for browser refreshes
        await persistPrivateKey(privateKey);

        connectSocket(authToken);

        setCryptoUnlocked(true);
    };

    /* =========================================
       AUTOMATIC SESSION RESTORATION
    ========================================= */

    useEffect(() => {
        let cancelled = false;

        const restoreSessionAutomatically = async () => {
            const savedToken = sessionStorage.getItem("token");

            if (!savedToken) {
                setToken(null);
                setRestoreLoading(false);
                return;
            }

            try {
                setRestoreLoading(true);
                setError("");

                // Restore private key from IndexedDB
                const privateKey = await restorePrivateKey();

                if (!privateKey) {
                    throw new Error(
                        "No saved encryption key was found on this device. Please log in again."
                    );
                }

                // Verify JWT and retrieve user profile
                const profileResponse = await fetch(
                    `${baseURL}/users/me`,
                    {
                        headers: {
                            Authorization: `Bearer ${savedToken}`,
                        },
                    }
                );

                const profileData = await profileResponse
                    .json()
                    .catch(() => ({}));

                if (!profileResponse.ok) {
                    const err = new Error(
                        profileData.message ||
                            "Unable to verify your session."
                    );

                    err.status = profileResponse.status;
                    throw err;
                }

                const currentUser = profileData.user;

                if (!currentUser?._id) {
                    throw new Error(
                        "Your account profile could not be restored."
                    );
                }

                if (cancelled) return;

                // Rebuild in-memory session
                setCryptoSession({
                    token: savedToken,
                    privateKey,
                    userId: currentUser._id,
                    name: currentUser.name,
                    email: currentUser.email,
                });

                if (!isCryptoSessionActive()) {
                    throw new Error(
                        "Session restoration failed."
                    );
                }

                connectSocket(savedToken);

                setToken(savedToken);
                setCryptoUnlocked(true);
                setError("");

            } catch (err) {
                console.error(
                    "SECUREX AUTOMATIC RESTORATION ERROR:",
                    err
                );

                if (cancelled) return;

                disconnectSocket();
                clearCryptoSession();

                setCryptoUnlocked(false);

                // Expired token or unavailable saved key:
                // return to the normal login screen.
                if (
                    err.status === 401 ||
                    err.status === 403 ||
                    err.message.includes("No saved encryption key")
                ) {
                    sessionStorage.removeItem("token");

                    setToken(null);

                    setError(
                        err.status === 401 || err.status === 403
                            ? "Your session has expired. Please log in again."
                            : "Your encryption key is not available on this device. Please log in again."
                    );
                } else {
                    // For network or IndexedDB errors, preserve the token.
                    setError(
                        err.message ||
                            "Unable to restore your SecureX session."
                    );
                }
            } finally {
                if (!cancelled) {
                    setRestoreLoading(false);
                }
            }
        };

        restoreSessionAutomatically();

        return () => {
            cancelled = true;
        };
    }, []);

    /* =========================================
       LOGIN / REGISTRATION
    ========================================= */

    const handleSubmit = async (event) => {
        event.preventDefault();
        setError("");

        const normalizedEmail = email.trim().toLowerCase();

        if (!GMAIL_REGEX.test(normalizedEmail)) {
            setError(
                "Please enter a valid Gmail address."
            );
            return;
        }

        if (
            password.length < 8 ||
            password.length > 128
        ) {
            setError(
                "Password must contain between 8 and 128 characters."
            );
            return;
        }

        if (isRegister) {
            if (
                name.trim().length < 2 ||
                name.trim().length > 50
            ) {
                setError(
                    "Name must contain between 2 and 50 characters."
                );
                return;
            }

            if (password !== confirmPassword) {
                setError("Passwords do not match.");
                return;
            }
        }

        try {
            setLoading(true);

            let response;

            if (isRegister) {
                response = await API.post(
                    "/auth/register",
                    {
                        name: name.trim(),
                        email: normalizedEmail,
                        password,
                        confirmPassword,
                    }
                );
            } else {
                response = await API.post(
                    "/auth/login",
                    {
                        email: normalizedEmail,
                        password,
                    }
                );
            }

            const receivedToken = response.data.token;

            if (!receivedToken) {
                throw new Error(
                    "Authentication token was not received."
                );
            }

            sessionStorage.setItem(
                "token",
                receivedToken
            );

            setToken(receivedToken);

            await initializeSecureSession(
                receivedToken,
                password
            );

            resetForm();

        } catch (err) {
            console.error(
                "SECUREX AUTHENTICATION ERROR:",
                err
            );

            disconnectSocket();
            clearCryptoSession();

            sessionStorage.removeItem("token");

            try {
                await removePersistedPrivateKey();
            } catch (storageError) {
                console.error(
                    "Unable to clear saved private key:",
                    storageError
                );
            }

            setToken(null);
            setCryptoUnlocked(false);

            setError(
                err.response?.data?.message ||
                    err.message ||
                    "Authentication failed. Please try again."
            );
        } finally {
            setLoading(false);
        }
    };

    /* =========================================
       LOGOUT
    ========================================= */

    const handleLogout = async () => {
        disconnectSocket();
        clearCryptoSession();

        sessionStorage.removeItem("token");

        setToken(null);
        setCryptoUnlocked(false);

        try {
            await removePersistedPrivateKey();
        } catch (err) {
            console.error(
                "SECUREX PRIVATE KEY CLEANUP ERROR:",
                err
            );
        }

        resetForm();
        setIsRegister(false);
    };

    /* =========================================
       RESTORATION LOADING SCREEN
    ========================================= */

    if (token && restoreLoading) {
        return (
            <main className="reference-login-page">
                <div className="reference-background">
                    <div className="reference-binary" />
                    <div className="reference-emblem" />
                    <div className="reference-vignette" />
                </div>

                <section className="reference-login-card">
                    <header className="reference-login-header">
                        <div className="securex-brand">
                            Secure<span>X</span>
                        </div>

                        <div className="reference-security-icon">
                            <i className="bi bi-shield-lock-fill" />
                        </div>
                    </header>

                    <div className="reference-login-body">
                        <p className="reference-description">
                            Restoring your secure session...
                        </p>

                        <div className="reference-login-footer">
                            <span className="status-indicator" />
                            SECUREX SESSION RESTORATION
                        </div>
                    </div>
                </section>
            </main>
        );
    }

    /* =========================================
       AUTHENTICATED AND UNLOCKED
    ========================================= */

    if (
        token &&
        cryptoUnlocked &&
        isCryptoSessionActive()
    ) {
        return <ChatLayout onLogout={handleLogout} />;
    }

    /* =========================================
       ORIGINAL LOGIN / REGISTER SCREEN
       PRESERVED
    ========================================= */

    return (
        <main className="reference-login-page">
            <div className="reference-background">
                <div className="reference-binary" />
                <div className="reference-emblem" />
                <div className="reference-vignette" />
            </div>

            <section className="reference-login-card">
                <header className="reference-login-header">
                    <div className="securex-brand">
                        Secure<span>X</span>
                    </div>

                    <div className="reference-security-icon">
                        <i className="bi bi-shield-lock-fill" />
                    </div>
                </header>

                <div className="reference-login-body">
                    <p className="reference-description">
                        {isRegister
                            ? "Create your secure communication identity."
                            : "Please enter your credentials to proceed."}
                    </p>

                    <form onSubmit={handleSubmit}>
                        {isRegister && (
                            <div className="reference-field">
                                <label htmlFor="securex-name">
                                    DISPLAY NAME
                                </label>

                                <input
                                    id="securex-name"
                                    type="text"
                                    value={name}
                                    onChange={(e) =>
                                        setName(e.target.value)
                                    }
                                    placeholder="Enter your name"
                                    autoComplete="name"
                                    maxLength={50}
                                    required
                                />
                            </div>
                        )}

                        <div className="reference-field">
                            <label htmlFor="securex-email">
                                GMAIL IDENTIFIER
                            </label>

                            <input
                                id="securex-email"
                                type="email"
                                value={email}
                                onChange={(e) =>
                                    setEmail(e.target.value)
                                }
                                placeholder="Enter your Gmail address"
                                autoComplete="email"
                                required
                            />
                        </div>

                        <div className="reference-field">
                            <label htmlFor="securex-password">
                                ACCESS KEY
                            </label>

                            <AsteriskPasswordInput
                                id="securex-password"
                                value={password}
                                onChange={setPassword}
                                placeholder="Enter your password"
                                autoComplete={
                                    isRegister
                                        ? "new-password"
                                        : "current-password"
                                }
                            />
                        </div>

                        {isRegister && (
                            <div className="reference-field">
                                <label htmlFor="securex-confirm-password">
                                    CONFIRM ACCESS KEY
                                </label>

                                <AsteriskPasswordInput
                                    id="securex-confirm-password"
                                    value={confirmPassword}
                                    onChange={setConfirmPassword}
                                    placeholder="Re-enter your password"
                                    autoComplete="new-password"
                                />
                            </div>
                        )}

                        {error && (
                            <div
                                className="reference-error"
                                role="alert"
                            >
                                <i className="bi bi-exclamation-triangle-fill" />
                                <span>{error}</span>
                            </div>
                        )}

                        <div className="reference-login-actions">
                            <button
                                type="submit"
                                className="reference-login-button"
                                disabled={loading}
                            >
                                {loading
                                    ? "PLEASE WAIT..."
                                    : isRegister
                                        ? "REGISTER"
                                        : "LOGIN"}
                            </button>

                            <button
                                type="button"
                                className="reference-switch-button"
                                onClick={switchMode}
                                disabled={loading}
                            >
                                {isRegister
                                    ? "Already have an account? Login"
                                    : "Create an account"}
                            </button>
                        </div>
                    </form>

                    <div className="reference-login-footer">
                        <span className="status-indicator" />
                        SECUREX AUTHENTICATION INTERFACE
                    </div>
                </div>
            </section>
        </main>
    );
}

export default App;