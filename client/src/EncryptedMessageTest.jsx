import { useState, useEffect } from 'react'

import { unlockPrivateKey } from './utils/crypto'
import { setCryptoSession } from './utils/cryptoSession'

import {
    encryptMessageForRecipient,
    decryptStoredMessage
} from './utils/messageEncryption'

import {
    sendEncryptedMessage,
    getEncryptedMessages
} from './utils/messageService'

import {
    connectSocket,
    getSocket,
    joinConversation
} from './services/socket'

function EncryptedMessageTest() {
    const [token, setToken] = useState('')
    const [password, setPassword] = useState('')
    const [conversationId, setConversationId] = useState('')
    const [recipientId, setRecipientId] = useState('')
    const [userId, setUserId] = useState('')
    const [message, setMessage] = useState('')
    const [unlocked, setUnlocked] = useState(false)
    const [messages, setMessages] = useState([])
    const [status, setStatus] = useState('')
    const [socketStatus, setSocketStatus] = useState('Disconnected')

    // Unlock private key and connect Socket.IO
    const unlockAccount = async () => {
        try {
            setStatus('Retrieving encryption keys...')
            setUnlocked(false)

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
                throw new Error(data.message || 'Unable to retrieve keys')
            }

            if (!data.keys) {
                throw new Error('Encryption key data is missing from server')
            }

            const protectedData = {
                encryptedPrivateKey: data.keys.encryptedPrivateKey,
                salt: data.keys.salt,
                iv: data.keys.iv,
                iterations: data.keys.iterations || 600000
            }

            if (
                !protectedData.encryptedPrivateKey ||
                !protectedData.salt ||
                !protectedData.iv
            ) {
                throw new Error('Incomplete encryption key data')
            }

            setStatus('Unlocking private key...')

            const privateKey = await unlockPrivateKey(
                protectedData,
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
                throw new Error(
                    profileData.message || 'Unable to retrieve profile'
                )
            }

            const currentUserId = profileData.user._id

            setUserId(currentUserId)

            setCryptoSession({
                token: token.trim(),
                privateKey,
                userId: currentUserId
            })

            setStatus('Connecting to SecureX real-time messaging...')

            const socket = connectSocket(token.trim())

            socket.on('connect', () => {
                setSocketStatus('Connected')
                console.log('SecureX real-time connection established')
            })

            socket.on('disconnect', () => {
                setSocketStatus('Disconnected')
            })

            setUnlocked(true)
            setPassword('')

            setStatus('Account unlocked successfully!')

        } catch (error) {
            console.error('ACCOUNT UNLOCK ERROR:', error)

            setUnlocked(false)
            setStatus(`FAILED: ${error.message}`)
        }
    }


    // Join conversation and listen for messages and status updates
    useEffect(() => {
        if (!unlocked || !conversationId.trim()) {
            return
        }

        const socket = getSocket()

        if (!socket) {
            return
        }

        const activeConversationId = conversationId.trim()

        const handleConnect = () => {
            setSocketStatus('Connected')
            joinConversation(activeConversationId)
        }


        // Incoming encrypted message
        const handleIncomingMessage = async (encryptedMessage) => {
            try {
                if (
                    String(encryptedMessage.conversationId) !==
                    String(activeConversationId)
                ) {
                    return
                }

                const senderId =
                    typeof encryptedMessage.sender === 'object'
                        ? encryptedMessage.sender._id
                        : encryptedMessage.sender

                const plaintext = await decryptStoredMessage(encryptedMessage)

                const newMessage = {
                    id: encryptedMessage._id,
                    sender: encryptedMessage.sender?.name || 'Unknown user',
                    senderId: String(senderId),
                    plaintext,
                    deliveryStatus: encryptedMessage.deliveryStatus || 'sent'
                }

                setMessages(previousMessages => {
                    if (
                        previousMessages.some(
                            item => String(item.id) === String(newMessage.id)
                        )
                    ) {
                        return previousMessages
                    }

                    return [...previousMessages, newMessage]
                })

                // Only the recipient sends delivery/read acknowledgements
                if (
                    String(senderId) !== String(userId) &&
                    document.visibilityState === 'visible'
                ) {
                    socket.emit(
                        'message_delivered',
                        {
                            messageId: encryptedMessage._id,
                            conversationId: activeConversationId
                        },
                        response => {
                            if (response?.success) {
                                socket.emit('message_read', {
                                    messageId: encryptedMessage._id,
                                    conversationId: activeConversationId
                                })
                            }
                        }
                    )
                }

            } catch (error) {
                console.error('LIVE MESSAGE DECRYPTION ERROR:', error)

                setStatus(
                    `Incoming message decryption failed: ${error.message}`
                )
            }
        }


        // Receive delivery and read status changes
        const handleMessageStatus = (statusUpdate) => {
            if (
                String(statusUpdate.conversationId) !==
                String(activeConversationId)
            ) {
                return
            }

            setMessages(previousMessages =>
                previousMessages.map(item =>
                    String(item.id) === String(statusUpdate.messageId)
                        ? {
                            ...item,
                            deliveryStatus: statusUpdate.deliveryStatus
                        }
                        : item
                )
            )
        }


        if (socket.connected) {
            handleConnect()
        } else {
            socket.on('connect', handleConnect)
        }

        socket.on('new_encrypted_message', handleIncomingMessage)

        socket.on('message_status_updated', handleMessageStatus)

        return () => {
            socket.off('connect', handleConnect)
            socket.off('new_encrypted_message', handleIncomingMessage)
            socket.off('message_status_updated', handleMessageStatus)
        }

    }, [unlocked, conversationId, userId])


    // Encrypt and send message
    const handleSendMessage = async () => {
        try {
            if (!message.trim()) {
                return
            }

            setStatus('Encrypting message...')

            const clientMessageId = window.crypto.randomUUID()

            const encryptedPayload = await encryptMessageForRecipient(
                message,
                recipientId.trim(),
                clientMessageId
            )

            setStatus('Sending encrypted message...')

            const result = await sendEncryptedMessage(
                conversationId.trim(),
                encryptedPayload
            )

            if (result.success) {
                setMessage('')
                setStatus('Encrypted message sent successfully!')
            } else {
                setStatus('Message sending failed')
            }

        } catch (error) {
            console.error('SEND MESSAGE ERROR:', error)
            setStatus(`FAILED: ${error.message}`)
        }
    }


    // Retrieve and decrypt stored messages
    const handleLoadMessages = async () => {
        try {
            setStatus('Retrieving encrypted messages...')

            const encryptedMessages = await getEncryptedMessages(
                conversationId.trim()
            )

            const decryptedMessages = await Promise.all(
                encryptedMessages.map(async item => {
                    try {
                        const plaintext = await decryptStoredMessage(item)

                        const senderId =
                            typeof item.sender === 'object'
                                ? item.sender._id
                                : item.sender

                        // Acknowledge messages received from the other user
                        if (
                            String(senderId) !== String(userId) &&
                            document.visibilityState === 'visible'
                        ) {
                            const socket = getSocket()

                            if (socket?.connected) {
                                socket.emit(
                                    'message_delivered',
                                    {
                                        messageId: item._id,
                                        conversationId: conversationId.trim()
                                    },
                                    response => {
                                        if (response?.success) {
                                            socket.emit('message_read', {
                                                messageId: item._id,
                                                conversationId: conversationId.trim()
                                            })
                                        }
                                    }
                                )
                            }
                        }

                        return {
                            id: item._id,
                            sender: item.sender?.name || 'Unknown user',
                            senderId: String(senderId),
                            plaintext,
                            deliveryStatus: item.deliveryStatus || 'sent'
                        }

                    } catch (error) {
                        console.error(
                            `Message ${item._id} decryption failed:`,
                            error
                        )

                        return {
                            id: item._id,
                            sender: item.sender?.name || 'Unknown user',
                            plaintext: '[Unable to decrypt message]',
                            deliveryStatus: item.deliveryStatus || 'sent',
                            error: error.message
                        }
                    }
                })
            )

            setMessages(decryptedMessages)

            setStatus('Messages retrieved and processed!')

        } catch (error) {
            console.error('MESSAGE RETRIEVAL ERROR:', error)
            setStatus(`FAILED: ${error.message}`)
        }
    }


    // Display message status
    const getStatusLabel = (deliveryStatus) => {
        switch (deliveryStatus) {
            case 'sent':
                return '✓ Sent'

            case 'delivered':
                return '✓✓ Delivered'

            case 'read':
                return '✓✓ Read'

            default:
                return 'Sending...'
        }
    }


    return (
        <div style={containerStyle}>

            <h1>SecureX - Encrypted Messaging</h1>

            <p>Real-time encrypted communication</p>

            <p>
                Socket Status:
                <strong
                    style={{
                        color: socketStatus === 'Connected'
                            ? '#00e676'
                            : '#ff5252',
                        marginLeft: '8px'
                    }}
                >
                    {socketStatus}
                </strong>
            </p>

            <hr />

            <h3>Step 1: Unlock Account</h3>

            <input
                type="password"
                value={token}
                onChange={e => setToken(e.target.value)}
                placeholder="Paste your login token"
                style={inputStyle}
            />

            <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="Enter your account password"
                style={inputStyle}
            />

            <button
                onClick={unlockAccount}
                disabled={!token.trim() || !password}
            >
                Unlock Account
            </button>

            {unlocked && (
                <>

                    <hr />

                    <h3>Step 2: Conversation Details</h3>

                    <input
                        value={conversationId}
                        onChange={e => setConversationId(e.target.value)}
                        placeholder="Enter conversation MongoDB ID"
                        style={inputStyle}
                    />

                    <input
                        value={recipientId}
                        onChange={e => setRecipientId(e.target.value)}
                        placeholder="Enter recipient MongoDB ID"
                        style={inputStyle}
                    />

                    <hr />

                    <h3>Step 3: Send Encrypted Message</h3>

                    <textarea
                        value={message}
                        onChange={e => setMessage(e.target.value)}
                        placeholder="Type your message..."
                        rows="4"
                        style={{
                            ...inputStyle,
                            height: '100px'
                        }}
                    />

                    <button
                        onClick={handleSendMessage}
                        disabled={
                            !message.trim() ||
                            !conversationId.trim() ||
                            !recipientId.trim()
                        }
                    >
                        Encrypt and Send
                    </button>

                    <hr />

                    <h3>Step 4: Retrieve Messages</h3>

                    <button
                        onClick={handleLoadMessages}
                        disabled={!conversationId.trim()}
                    >
                        Load and Decrypt Messages
                    </button>

                    <h3>Conversation Messages</h3>

                    {messages.map(item => (
                        <div key={item.id} style={messageStyle}>

                            <strong>Sender: {item.sender}</strong>

                            <p style={{ marginTop: '10px' }}>
                                {item.plaintext}
                            </p>

                            <small
                                style={{
                                    color: item.deliveryStatus === 'read'
                                        ? '#4da6ff'
                                        : '#00e676'
                                }}
                            >
                                {getStatusLabel(item.deliveryStatus)}
                            </small>

                            {item.error && (
                                <p style={{ color: '#ff5252' }}>
                                    {item.error}
                                </p>
                            )}

                        </div>
                    ))}

                </>
            )}

            <hr />

            <h3>Status</h3>

            <p>{status}</p>

        </div>
    )
}


const containerStyle = {
    minHeight: '100vh',
    background: '#111',
    color: 'white',
    padding: '35px',
    fontFamily: 'Arial'
}

const inputStyle = {
    display: 'block',
    width: '500px',
    maxWidth: '100%',
    padding: '12px',
    marginBottom: '15px',
    borderRadius: '5px'
}

const messageStyle = {
    background: '#222',
    padding: '15px',
    marginTop: '15px',
    borderRadius: '8px'
}

export default EncryptedMessageTest