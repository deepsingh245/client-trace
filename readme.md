# client-trace

A comprehensive client-side security and telemetry library for modern web applications. `client-trace` provides a suite of modules to detect tampering, identify devices, monitor behavior, and secure data transport.

## Features

- **Integrity Verification**: Detect if your client bundle has been modified.
- **Network Analysis**: Detect monkey-patched `fetch`/`XHR`, proxies, and timing anomalies.
- **Device Fingerprinting**: Lightweight, privacy-friendly device identification.
- **Bot Detection**: Analyze mouse movements and click patterns to identify bots.
- **Security Monitoring**: Detect script injections, CSP violations, and local storage tampering.
- **Secure Transport**: End-to-end encryption (AES-GCM), payload signing (HMAC), and replay protection.
## Use Cases

- **Client‑side bundle integrity verification** – `verifyBundleIntegrity` ensures the running JavaScript bundle matches a known hash.
- **Session‑token generation** – `generateSessionToken` creates a signed token for API calls.
- **Network‑level API tampering detection** – `detectNetworkAPITampering` flags monkey‑patched `fetch`/`XHR`.
- **Proxy / VPN detection** – `detectProxy` measures latency and header anomalies.
- **Timing‑anomaly detection** – `detectTimingAnomalies` spots abnormal round‑trip times.
- **Device fingerprinting** – `getDeviceFingerprint` builds a privacy‑friendly device identifier.
- **Bot / headless‑browser detection** – `detectBot` analyses mouse entropy, rapid clicks, and headless flags.
- **Script‑injection monitoring** – `detectInjections` watches for unexpected `<script>` tags.
- **CSP violation listener** – `listenForCSPViolations` aggregates CSP breach events.
- **Local‑storage tampering detection** – `checkStorageIntegrity` validates stored data integrity.
- **Secure transport helpers** – `signPayload`, `encryptTelemetry`, `getNonce` provide signing, encryption, and replay protection.
- **Aggregated security report** – `collectSecurityReport` runs all checks and returns a single JSON payload.

## Installation

```bash
npm install client-trace
```

## Usage

### Quick Start (Aggregated Report)

The easiest way to use `client-trace` is to collect a full security report.

```javascript
import { collectSecurityReport } from 'client-trace';

const config = {
  bundleUrl: '/assets/main.js',
  expectedBundleHash: 'sha256-hash-of-your-bundle', // Optional
  pingUrl: '/api/ping', // For proxy/timing detection
  userUniqueId: 'user-123', // For session token
  hashedIp: 'hash-of-ip', // Provided by server
  secret: 'your-shared-secret' // For signing/encryption
};

collectSecurityReport(config).then(report => {
  console.log('Security Report:', report);
  // Send report to your server
});
```

### Modular Usage

You can also import and use individual modules as needed.

#### 1. Bundle Integrity
```javascript
import { verifyBundleIntegrity } from 'client-trace';

verifyBundleIntegrity('/main.js', 'expected-hash').then(result => {
  if (!result.integrityOk) {
    console.error('Bundle tampered!', result.actualHash);
  }
});
```

#### 2. Network Tampering Detection
```javascript
import { detectNetworkAPITampering } from 'client-trace';

const result = detectNetworkAPITampering();
if (result.tampered) {
  console.warn('Network APIs modified:', result.tamperedFunctions);
}
```

#### 3. Device Fingerprinting
```javascript
import { getDeviceFingerprint } from 'client-trace';

getDeviceFingerprint().then(({ fingerprintHash, components }) => {
  console.log('Device ID:', fingerprintHash);
});
```

#### 4. Bot Detection
```javascript
import { startBehaviorMonitoring, detectBot } from 'client-trace';

// Start monitoring early in the session
startBehaviorMonitoring();

// Check later (e.g., before form submission)
const botCheck = detectBot();
if (botCheck.botLikely) {
  console.warn('Bot detected!', botCheck.signals);
}
```

#### 5. Secure Transport (Encryption)
```javascript
import { encryptTelemetry, decryptTelemetry } from 'client-trace';

const payload = { event: 'login', timestamp: Date.now() };
const secret = 'shared-secret-key';

encryptTelemetry(payload, secret).then(encrypted => {
  // Send `encrypted` object to server
  console.log('Encrypted:', encrypted);
});
```

## Modules Overview

| Category | Module | Description |
|----------|--------|-------------|
| **Integrity** | `verifyBundleIntegrity` | Checks if the script file matches expected hash. |
| | `generateSessionToken` | Creates a signed token binding user to IP/UA. |
| **Network** | `detectNetworkAPITampering` | Checks if `fetch` or `XHR` are native code. |
| | `detectProxy` | Inspects headers for proxy signatures. |
| | `detectTimingAnomalies` | Measures DNS/TTFB to find MITM delays. |
| **Fingerprint** | `getDeviceFingerprint` | Hashes non-unique signals (screen, OS, timezone). |
| | `detectBot` | Analyzes entropy of mouse moves and clicks. |
| **Security** | `detectInjections` | Monitors DOM for new `<script>` tags. |
| | `listenForCSPViolations` | Captures CSP violation events. |
| | `checkStorageIntegrity` | Verifies `localStorage` hasn't been changed externally. |
| **Transport** | `signPayload` | Signs data with HMAC-SHA256. |
| | `encryptTelemetry` | Encrypts data with AES-GCM. |
| | `getNonce` | Generates rotating nonce for replay protection. |

## License

ISC
