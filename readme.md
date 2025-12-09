# client-trace Backend Server

[![npm version](https://img.shields.io/npm/v/client-trace.svg)](https://www.npmjs.com/package/client-trace)

This repository hosts the **client-trace** backend server, now distributed as an npm package. The server provides API endpoints to support the client-side security library, handling integrity checks, device fingerprinting, bot detection, and secure transport.

## 📦 Installation

```bash
npm install -g client-trace   # install globally to use the CLI
# or as a dependency in your project
npm install client-trace
```

## 🚀 Getting Started

After installing, you can run the server directly:

```bash
node -e "import('client-trace/server.js').then(m => m.default())"   # ES module import
# or, if installed globally
client-trace
```

The server starts on **port 5000** by default.

```text
Test server running at http://localhost:5000/
```

## 📡 API Endpoints

The server exposes the following endpoints to support the client SDK:

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
