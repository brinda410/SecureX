import { useState } from 'react'

import { unlockPrivateKey } from './utils/crypto'
import { setCryptoSession } from './utils/cryptoSession'
import { fetchUserPublicKey } from './utils/publicKeyService'

function PublicKeyTest() {
    const [token, setToken] = useState('')
    const [password, setPassword] = useState('')
    const [userId, setUserId] = useState('')

    const [unlocked, setUnlocked] = useState(false)
    const [result, setResult] = useState(null)
    const [sharedFingerprint, setSharedFingerprint] = useState('')
    const [verification, setVerification] = useState('')
    const [status, setStatus] = useState('')

    const unlockKey = async () => {
        try {
            setStatus('Retrieving encryption keys...')

            const response = await fetch(
                'http://localhost:5000/api/users/keys/me',
                {
                    headers: {
                        Authorization: `Bearer ${token.trim()}`
                    }
                }
            )

            const data = await response.json()

            if (!response.ok) {
                throw new Error(data.message)
            }

            const privateKey = await unlockPrivateKey(
                {
                    encryptedPrivateKey: data.keys.encryptedPrivateKey,
                    salt: data.keys.salt,
                    iv: data.keys.iv
                },
                password
            )

            const profileResponse = await fetch(
                'http://localhost:5000/api/users/me',
                {
                    headers: {
                        Authorization: `Bearer ${token.trim()}`
                    }
                }
            )

            const profileData = await profileResponse.json()

            if (!profileResponse.ok) {
                throw new Error(profileData.message)
            }

            setCryptoSession({
                token: token.trim(),
                privateKey,
                userId: profileData.user._id
            })

            setUnlocked(true)
            setPassword('')
            setStatus('Private key unlocked successfully!')

        } catch (error) {
            setUnlocked(false)
            setStatus(`FAILED: ${error.message}`)
        }
    }

    const retrieveKey = async () => {
        try {
            setResult(null)
            setVerification('')
            setSharedFingerprint('')
            setStatus('Retrieving recipient public key...')

            const keyData = await fetchUserPublicKey(userId.trim())

            setResult(keyData)
            setStatus('Public key retrieved successfully!')

        } catch (error) {
            setStatus(`FAILED: ${error.message}`)
        }
    }

    const copyFingerprint = async () => {
        try {
            await navigator.clipboard.writeText(result.fingerprint)
            setStatus('Fingerprint copied successfully!')
        } catch {
            setStatus('Unable to copy. Please copy the fingerprint manually.')
        }
    }

    const verifyFingerprint = () => {
        const actual = result.fingerprint
            .replace(/[^a-fA-F0-9]/g, '')
            .toUpperCase()

        const supplied = sharedFingerprint
            .replace(/[^a-fA-F0-9]/g, '')
            .toUpperCase()

        if (!supplied || supplied.length !== 64) {
            setVerification('INVALID')
            return
        }

        if (actual === supplied) {
            setVerification('MATCH')
        } else {
            setVerification('MISMATCH')
        }
    }

    return (
        <div style={{
            minHeight: '100vh',
            background: '#111',
            color: 'white',
            padding: '40px',
            fontFamily: 'Arial'
        }}>

            <h1>SecureX - Public Key Verification</h1>

            <h3>Step 1: Unlock Your Private Key</h3>

            <input
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="Paste your login token"
                style={{
                    display: 'block',
                    width: '500px',
                    padding: '10px',
                    marginBottom: '15px'
                }}
            />

            <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your account password"
                style={{
                    display: 'block',
                    width: '500px',
                    padding: '10px',
                    marginBottom: '15px'
                }}
            />

            <button
                onClick={unlockKey}
                disabled={!token.trim() || !password}
            >
                Unlock Private Key
            </button>

            {unlocked && (
                <>
                    <h3>Step 2: Retrieve Recipient's Public Key</h3>

                    <input
                        value={userId}
                        onChange={(e) => setUserId(e.target.value)}
                        placeholder="Paste recipient's MongoDB ID"
                        style={{
                            display: 'block',
                            width: '500px',
                            padding: '10px',
                            marginBottom: '15px'
                        }}
                    />

                    <button
                        onClick={retrieveKey}
                        disabled={!userId.trim()}
                    >
                        Retrieve Public Key
                    </button>
                </>
            )}

            <h3>Status</h3>
            <p>{status}</p>

            {result && (
                <div style={{ marginTop: '30px' }}>

                    <h3>Recipient: {result.name}</h3>

                    <h4>SHA-256 Fingerprint</h4>

                    <p style={{ overflowWrap: 'anywhere' }}>
                        {result.fingerprint}
                    </p>

                    <button onClick={copyFingerprint}>
                        Copy Fingerprint
                    </button>

                    <hr style={{ margin: '30px 0' }} />

                    <h3>Step 3: Verify Fingerprint</h3>

                    <p>
                        Ask the recipient to share their fingerprint
                        through an independent trusted channel.
                    </p>

                    <textarea
                        value={sharedFingerprint}
                        onChange={(e) => {
                            setSharedFingerprint(e.target.value)
                            setVerification('')
                        }}
                        placeholder="Paste the fingerprint shared by the recipient"
                        rows="4"
                        style={{
                            display: 'block',
                            width: '500px',
                            padding: '10px',
                            marginBottom: '15px'
                        }}
                    />

                    <button
                        onClick={verifyFingerprint}
                        disabled={!sharedFingerprint.trim()}
                    >
                        Verify Fingerprint
                    </button>

                    {verification === 'MATCH' && (
                        <h3 style={{ color: '#00e676' }}>
                            VERIFIED - Fingerprints match!
                        </h3>
                    )}

                    {verification === 'MISMATCH' && (
                        <h3 style={{ color: '#ff4444' }}>
                            WARNING - Fingerprints do not match!
                        </h3>
                    )}

                    {verification === 'INVALID' && (
                        <h3 style={{ color: '#ffc107' }}>
                            Invalid fingerprint. Please enter a valid
                            64-character SHA-256 fingerprint.
                        </h3>
                    )}

                </div>
            )}

        </div>
    )
}

export default PublicKeyTest