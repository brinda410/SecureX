import { useState } from "react";

import { unlockPrivateKey } from "./utils/crypto";

import { setCryptoSession } from "./utils/cryptoSession";

function CryptoTest() {
const [token, setToken] = useState("");
const [password, setPassword] = useState("");
const [status, setStatus] = useState("");
const [success, setSuccess] = useState(false);
const [loading, setLoading] = useState(false);

const unlockKey = async () => {
try {
setLoading(true);
setSuccess(false);

  const cleanToken = token.trim();

  if (!cleanToken || !password) {
    throw new Error("Token and password are required.");
  }

  setStatus("Retrieving protected encryption keys...");

  const response = await fetch(
    "http://localhost:5000/api/users/keys/me",
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${cleanToken}`,
      },
    }
  );

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      data.message || "Unable to retrieve encryption keys."
    );
  }

  if (
    !data.keys?.encryptedPrivateKey ||
    !data.keys?.salt ||
    !data.keys?.iv
  ) {
    throw new Error("Protected private key data is incomplete.");
  }

  setStatus("Unlocking private key...");

  const privateKey = await unlockPrivateKey(
    {
      encryptedPrivateKey: data.keys.encryptedPrivateKey,
      salt: data.keys.salt,
      iv: data.keys.iv,
    },
    password
  );

  if (!privateKey) {
    throw new Error("Private key could not be unlocked.");
  }

  setStatus("Retrieving account profile...");

  const profileResponse = await fetch(
    "http://localhost:5000/api/users/me",
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${cleanToken}`,
      },
    }
  );

  const profileData = await profileResponse.json();

  if (!profileResponse.ok) {
    throw new Error(
      profileData.message || "Unable to retrieve account profile."
    );
  }

  const user = profileData.user;

  if (!user?._id || !user?.name || !user?.email) {
    throw new Error("Account profile information is incomplete.");
  }

  setCryptoSession({
    token: cleanToken,
    privateKey,
    userId: user._id,
    name: user.name,
    email: user.email,
  });

  setSuccess(true);

  setStatus(
    `Welcome, ${user.name}! Your encryption session is ready.`
  );

  setPassword("");

} catch (error) {
  console.error("Private key unlock error:", error);

  setSuccess(false);
  setStatus(`FAILED: ${error.message}`);

} finally {
  setLoading(false);
}

};

return (
<div
style={{
minHeight: "100vh",
background: "#111",
color: "white",
padding: "40px",
fontFamily: "Arial",
}}
> <h1>SecureX - Private Key Unlock</h1>

  <p>
    Unlock your encrypted RSA private key to start
    secure communication.
  </p>

  <div style={{ maxWidth: "500px" }}>
    <label>Login Token</label>

    <textarea
      value={token}
      onChange={(event) => setToken(event.target.value)}
      placeholder="Paste your login token"
      rows="4"
      style={{
        width: "100%",
        padding: "10px",
        marginBottom: "20px",
      }}
    />

    <label>Account Password</label>

    <input
      type="password"
      value={password}
      onChange={(event) => setPassword(event.target.value)}
      placeholder="Enter your account password"
      style={{
        width: "100%",
        padding: "10px",
        marginBottom: "20px",
      }}
    />

    <button
      onClick={unlockKey}
      disabled={!token.trim() || !password || loading}
      style={{
        padding: "12px 24px",
        background: "#dc3545",
        color: "white",
        border: "none",
        cursor: "pointer",
      }}
    >
      {loading ? "Unlocking..." : "Unlock Private Key"}
    </button>

    <h3 style={{ marginTop: "25px" }}>Status</h3>

    <p>{status}</p>

    {success && (
      <h3 style={{ color: "#4ade80" }}>
        Private key unlocked successfully!
      </h3>
    )}
  </div>
</div>

);
}

export default CryptoTest;
