# client-trace Backend Server

This repository hosts the **Test Server** for the `client-trace` security library. It is a standalone Node.js server designed to verify the functionality of the [client-trace npm package](https://www.npmjs.com/package/client-trace) by handling telemetry, integrity checks, and security reports.

## 🚀 Running the Test Server

This server is intended to be run directly to support client-side testing.

```bash
# Clone the repository (if you haven't already)
# git clone ...

# Install dependencies (only internal dev dependencies if any, or just run node)
# Currently, the server has no external dependencies.

# Start the server
node server.js
```

The server starts on **port 5000** by default.

```text
Test server running at http://localhost:5000/
```

> **Note**: This server provides the backend API endpoints required by the `client-trace` library. To use the security features in your frontend application, install the library: `npm install client-trace`.

The server starts on **port 5000** by default.

```text
Test server running at http://localhost:5000/
```

## 📡 API Endpoints

The server exposes the following endpoints to support the client SDK:

### Integrity Checks
- **GET** `/api/integrity/bundle`
  - Serves a clean mock JavaScript bundle for integrity verification tests.
  - **Returns**: `text/javascript` content (`console.log('Valid Bundle');`).

- **GET** `/api/integrity/bundle-tampered`
  - Serves a tampered mock JavaScript bundle.
  - **Returns**: `text/javascript` content with appended tamper code.

### Authentication
- **POST** `/api/auth/session`
  - Generates a signed session token binding the user to their IP.
  - **Body**: `{ "userId": "string", "ipHash": "string", "secret": "string" }`
  - **Returns**: `{ "token": "string", "expiry": number }`

### Network Analysis
- **GET** `/api/network/detect-proxy`
  - Inspects headers to detect proxy usage.
  - **Query Params**: `?simulate=true` (simulates proxy headers for testing)
  - **Returns**: JSON reflecting `Via`, `X-Forwarded-For`, etc.

- **GET** `/api/network/timing`
  - Measures latency and detects timing anomalies.
  - **Returns**: `{ "timestamp": number }`

### Device Fingerprinting
- **POST** `/api/fingerprint`
  - Receives the device fingerprint hash from the client.
  - **Body**: `{ "fingerprintHash": "string", ... }`
  - **Returns**: `{ "received": true, "serverTime": number }`

### Bot Detection
- **POST** `/api/bot-detection`
  - Validates the bot detection analysis performed by the client.
  - **Body**: `{ "result": { "botLikely": boolean, ... } }`
  - **Returns**: `{ "verdict": "bot" | "human" }`

### Secure Transport
- **POST** `/api/transport/verify-signature`
  - Verifies the HMAC signature of a payload.
  - **Body**: `{ "payload": object, "signature": "string", "secret": "string" }`
  - **Returns**: `{ "isValid": boolean }`

- **POST** `/api/transport/decrypt`
  - Decrypts AES‑GCM encrypted telemetry data.
  - **Body**: `{ "encryptedData": { "ciphertext": "base64", "iv": "base64", "authTag": "base64", "salt": "base64" }, "secret": "string" }`
  - **Returns**: Decrypted JSON object or an error.

### Security Reports
- **POST** `/api/csp-report`
  - Endpoint for browser CSP violation reports.

## 📚 Usage Example (Node)

```javascript
import { createServer } from 'http';
import server from 'client-trace/server.js';

// The imported module starts the server automatically when required.
```

## 🛠️ Development

If you need to modify the server, clone the repository and run:

```bash
npm install
node server.js
```

## 📄 License

ISC
