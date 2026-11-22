# SecureX

### Secure End-to-End Encrypted Real-Time Messaging Platform

**Privacy by Design. Encryption by Default. Security at Every Layer.**

SecureX is a full-stack, real-time messaging application built around client-side end-to-end encryption (E2EE). It uses a hybrid cryptographic architecture combining AES-256-GCM for message encryption and RSA-OAEP for cryptographic key protection. The platform supports private and group conversations, authenticated real-time communication, encrypted message storage, and application-level security controls.

**Live Application:** [Launch SecureX](https://secure-x-silk.vercel.app/)  

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Application Screenshots](#application-screenshots)
- [System Architecture](#system-architecture)
- [Cryptographic Architecture](#cryptographic-architecture)
- [Security Architecture](#security-architecture)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Environment Configuration](#environment-configuration)
- [Running the Application](#running-the-application)
- [Deployment](#deployment)
- [Security Considerations](#security-considerations)
- [Future Enhancements](#future-enhancements)
- [License](#license)

---

## Overview

SecureX explores the implementation of privacy-focused communication through browser-side encryption and secure backend infrastructure.

Unlike conventional messaging architectures in which message content is transmitted to and stored by the server in plaintext, SecureX is designed to encrypt message content on the client before transmission.

The backend handles authentication, conversation management, encrypted message persistence, and real-time delivery without requiring plaintext message content for its core messaging operations.

The application brings together cryptographic primitives, real-time communication protocols, database persistence, and web application security practices in a single full-stack system.

### Design Objectives

- Protect message confidentiality through client-side encryption.
- Separate message encryption from cryptographic key management.
- Support both individual and group conversations.
- Provide authenticated real-time message delivery.
- Store encrypted message payloads rather than plaintext message content.
- Apply security controls across authentication, API access, and communication layers.

---

## Key Features

### End-to-End Encrypted Messaging
- Client-side message encryption before transmission.
- AES-256-GCM authenticated encryption.
- RSA-OAEP-based encryption key protection.
- Message decryption performed by authorized clients.
- Tamper detection through authenticated encryption.

### Real-Time Communication
- Socket.IO-powered real-time messaging.
- Authenticated socket connections.
- Conversation-based message delivery.
- Message synchronization and read-status updates.

### Group Communication
- Group conversation creation and management.
- Group member and administrator functionality.
- Recipient-specific encrypted key envelopes.
- Group encryption key rotation.

### Messaging Capabilities
- One-to-one and group conversations.
- Text messaging.
- Image and document attachments.
- Audio and video file attachments.
- Message replies and editing.
- Message deletion and read receipts.
- Can share links.

### Authentication and Access Control
- User registration and login.
- JWT-based authentication.
- Password validation.
- Authenticated API access.
- Protected communication sessions.

### Application Security
- Security-oriented HTTP headers through Helmet.
- API rate limiting.
- CORS configuration.
- Authentication and authorization middleware.
- Input validation and controlled request handling.

---

## Application Screenshots

Screenshots can be added to `docs/screenshots/` and referenced below.

| Application Interface | Screenshot |
|---|---|
| Login | <img width="955" height="497" alt="Screenshot 2026-11-22 222310" src="https://github.com/user-attachments/assets/8ddcab99-ba75-4351-849c-395b9a0433fa" />|
| Registration | <img width="959" height="493" alt="Screenshot 2026-11-22 222353" src="https://github.com/user-attachments/assets/4a6ba665-097a-480a-aa97-c62f14db5e10" />|
| Main Dashboard | <img width="956" height="497" alt="Screenshot 2026-11-22 222709" src="https://github.com/user-attachments/assets/6e48b254-8fd9-432d-9d4c-06c3f1c6cea6" />|
| Group Conversation | <img width="959" height="500" alt="Screenshot 2026-11-22 222801" src="https://github.com/user-attachments/assets/187f8ba2-2a12-40a9-8e40-aca9ad8e0554" />|
| Security Panel |<img width="955" height="496" alt="Screenshot 2026-11-22 222831" src="https://github.com/user-attachments/assets/acd8d7a5-26c9-4088-96d4-5980e57b596f" />
|

---

## System Architecture

SecureX follows a client-server architecture with a dedicated client-side cryptographic layer.

### Architecture Diagram

<img width="1536" height="1024" alt="SecureX System Architecture Infographic" src="https://github.com/user-attachments/assets/00925646-0457-4f86-8bb0-c18da2a9b298" />

### Architectural Components

| Component | Responsibility |
|---|---|
| React Client | User interface and conversation management |
| Client Cryptographic Layer | Message encryption, decryption, and key handling |
| REST API | Authentication and application operations |
| Socket.IO | Real-time communication and message delivery |
| Express Server | Request processing and backend application logic |
| Authentication Middleware | JWT verification and access control |
| MongoDB | Persistence of users, conversations, and encrypted message data |

---

## Cryptographic Architecture

SecureX uses a hybrid cryptographic approach to separate bulk message encryption from encryption key protection.

### Cryptographic Algorithms

| Algorithm | Purpose |
|---|---|
| AES-256-GCM | Authenticated message encryption |
| RSA-OAEP-SHA256 | Encryption and protection of message encryption keys |
| PBKDF2-SHA256 | Password-based key derivation |

### Message Encryption Workflow

1. The sender's client prepares the message for encryption.
2. A symmetric AES-256 key is used to encrypt the message using AES-256-GCM.
3. The corresponding encryption key is protected using RSA-OAEP.
4. The encrypted message and associated cryptographic metadata are transmitted to the backend.
5. The backend persists the encrypted payload.
6. The recipient retrieves the encrypted message.
7. The recipient's client uses its authorized key material to recover the AES key and decrypt the message.

### Encrypted Message Data

The message encryption structure includes fields such as:

| Field | Description |
|---|---|
| `ciphertext` | Encrypted message content |
| `iv` | Initialization vector used by AES-GCM |
| `wrappedAESKey` | RSA-protected AES encryption key |
| `senderWrappedAESKey` | Sender-accessible encrypted key envelope |
| `recipientKeyEnvelopes` | Recipient-specific encrypted key material |
| `algorithm` | Message encryption algorithm identifier |
| `keyEncryptionAlgorithm` | Key protection algorithm identifier |

**Important:** Encryption protects message content, but it does not automatically conceal all metadata. Information such as account identifiers, conversation relationships, timestamps, and communication patterns may still be processed by the application infrastructure.

---

## Security Architecture

Security is incorporated into multiple layers of the application.

| Layer | Security Mechanism |
|---|---|
| Message confidentiality | Client-side AES-256-GCM encryption |
| Key protection | RSA-OAEP-SHA256 |
| Authentication | JSON Web Tokens |
| API protection | Authentication and authorization middleware |
| Request protection | Rate limiting |
| HTTP security | Helmet security headers |
| Cross-origin access | Configured CORS policy |
| Message integrity | AES-GCM authenticated encryption |
| Group key management | Recipient-specific key envelopes and key rotation |

### OWASP Security Considerations

SecureX incorporates application-level controls relevant to the OWASP Top 10 risk categories.

| OWASP Risk Area | Relevant Application Controls |
|---|---|
| Broken Access Control | JWT authentication and protected routes |
| Cryptographic Failures | Client-side encryption and protected key handling |
| Injection | Input validation and controlled database operations |
| Insecure Design | Security-oriented application and cryptographic architecture |
| Security Misconfiguration | Helmet and controlled CORS configuration |
| Authentication Failures | Password validation and JWT-based authentication |
| Software and Data Integrity Failures | Authenticated encryption and controlled application dependencies |
| Security Logging and Monitoring Failures | Logging and monitoring improvements remain an area for further development |

These controls represent implementation considerations, not a claim of OWASP certification or a completed independent security audit. Security testing should be performed against the deployed application and its actual configuration.

---

## Technology Stack

### Frontend
- React
- Vite
- JavaScript
- HTML5
- CSS3
- Bootstrap

### Backend
- Node.js
- Express.js
- Socket.IO

### Database
- MongoDB Atlas
- Mongoose

### Cryptography and Authentication
- Web Crypto API
- AES-256-GCM
- RSA-OAEP-SHA256
- PBKDF2-SHA256
- JSON Web Tokens (JWT)

### Security
- Helmet
- Express Rate Limit
- CORS
- Authentication and authorization middleware

### Deployment and Development
- Git
- GitHub
- Vercel
- Render

---

## Project Structure

The repository is organized into separate frontend and backend applications.

```text
Secure_Chat_Encryption/
│
├── client/
│   ├── public/
│   │   └── favicon.ico
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   └── ...
│   ├── package.json
│   └── ...
│
├── server/
│   ├── controllers/
│   ├── middleware/
│   ├── models/
│   ├── routes/
│   ├── services/
│   ├── package.json
│   └── ...
│
├── docs/
│   ├── architecture/
│   │   └── securex-architecture.png
│   └── screenshots/
│
├── README.md
└── LICENSE
```

*The tree is representative. Update directory names to match the actual repository structure.*

---

## Getting Started

Follow these steps to run SecureX locally.

### Prerequisites

Install the following:

- Node.js (LTS recommended)
- npm
- Git
- A MongoDB Atlas account or compatible MongoDB instance

### 1. Clone the Repository

```bash
git clone https://github.com/brinda410/Secure_Chat_Encryption.git
cd Secure_Chat_Encryption
```

### 2. Install Backend Dependencies

```bash
cd server
npm install
```

### 3. Configure the Backend

Create a `.env` file inside the `server` directory and configure the required environment variables.

See [Environment Configuration](#environment-configuration).

### 4. Start the Backend

```bash
npm run dev
```

### 5. Install Frontend Dependencies

Open a separate terminal:

```bash
cd Secure_Chat_Encryption/client
npm install
```

### 6. Configure and Start the Frontend

Create the frontend `.env` file and configure the backend API URL.

```bash
npm run dev
```

Open the local Vite URL displayed in your terminal.

---

## Environment Configuration

### Backend Environment

Example configuration:

```env
PORT=5000
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_secure_random_secret
JWT_ISSUER=securex-api
JWT_AUDIENCE=securex-client
CLIENT_URL=http://localhost:5173
NODE_ENV=development
```

### Frontend Environment

```env
VITE_API_URL=http://localhost:5000
```

**Configuration note:** These are example variable names based on the project's documented setup. Verify them against the actual backend and frontend configuration before deployment. Never commit `.env` files, database credentials, or JWT secrets to GitHub.

---

## Running the Application

Once both services are running:

1. Open the frontend in your browser.
2. Register a new account.
3. Log in using your credentials.
4. Open or create a conversation.
5. Exchange encrypted messages.
6. Create a group conversation to explore group messaging.
7. Test supported attachments and message-management features.
8. Inspect the security panel and encryption-related information.

### Live Demo

**[Open the SecureX Application](https://secure-x-silk.vercel.app/)**

The deployed frontend communicates with the backend hosted on Render. The backend may take additional time to respond after periods of inactivity due to hosting cold starts.

---

## Deployment

SecureX uses separate hosting services for its frontend and backend.

| Application Component | Hosting Platform | Deployment |
|---|---|---|
| Frontend | Vercel | [SecureX Live Application](https://secure-x-silk.vercel.app/) |
| Backend | Render | [SecureX API](https://securex-oiae.onrender.com) |
| Source Code | GitHub | [SecureX Repository](https://github.com/brinda410/Secure_Chat_Encryption) |

Deployment configuration should include the correct frontend API URL, backend CORS origins, database connection string, and JWT configuration.

Production secrets must be configured through the hosting provider's environment-variable settings rather than committed to the repository.

---

## Security Considerations

SecureX is a security-focused application, but the presence of encryption algorithms alone does not establish complete system security.

The following areas are important when evaluating or extending the implementation:

- Ensure AES-GCM initialization vectors are never reused with the same encryption key.
- Protect private key material and avoid exposing it through logs or application responses.
- Validate authorization independently for every protected conversation operation.
- Restrict file uploads by type, size, and content validation.
- Avoid exposing sensitive message content through logs, previews, or error responses.
- Review JWT expiration, signing configuration, and secret management.
- Test group membership changes and key rotation against unauthorized access scenarios.
- Conduct security testing against the deployed application.

An independent penetration test and formal cryptographic audit have not been claimed by this documentation.

---

## Future Enhancements

Potential areas for continued development include:

- Double Ratchet protocol integration.
- Forward secrecy and post-compromise security.
- Multi-device key synchronization.
- Enhanced attachment encryption and secure file handling.
- Comprehensive automated security testing.
- Security event monitoring and audit trails.
- Improved key recovery and device management.
- Independent cryptographic review and penetration testing.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Project Links

- **Live Application:** https://secure-x-silk.vercel.app/
- **Backend:** https://securex-oiae.onrender.com
- **GitHub Repository:** https://github.com/brinda410/Secure_Chat_Encryption

---

**SecureX — Privacy by Design. Encryption by Default. Security at Every Layer.**
