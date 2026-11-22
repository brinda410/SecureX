// SecureX - Message API Service

import { getCryptoSession } from './cryptoSession'

const API_URL = `${import.meta.env.VITE_API_URL || "/api"}/messages`;


// Send an encrypted message to the backend
export const sendEncryptedMessage = async (
    conversationId,
    encryptedPayload
) => {
    const session = getCryptoSession()

    if (!session.token) {
        throw new Error('Please log in first')
    }

    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${session.token}`
            },
            body: JSON.stringify({
                conversationId,
                ...encryptedPayload
            })
        })

        const data = await response.json()

        if (!response.ok) {
            throw new Error(data.message || 'Message sending failed')
        }

        return data

    } catch (error) {
        console.error('Send message error:', error)
        throw error
    }
}


// Retrieve encrypted messages from a conversation
export const getEncryptedMessages = async (conversationId) => {
    const session = getCryptoSession()

    if (!session.token) {
        throw new Error('Please log in first')
    }

    try {
        const response = await fetch(
            `${API_URL}/${conversationId}`,
            {
                method: 'GET',
                headers: {
                    Authorization: `Bearer ${session.token}`
                }
            }
        )

        const data = await response.json()

        if (!response.ok) {
            throw new Error(data.message || 'Unable to retrieve messages')
        }

        return data.messages

    } catch (error) {
        console.error('Get messages error:', error)
        throw error
    }
}