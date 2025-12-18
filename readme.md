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

##### `verifyBundleIntegrity(bundleUrl, expectedHash)`

Verifies that your client bundle hasn't been tampered with by comparing its SHA-256 hash against a known good hash.

**Parameters:**
- `bundleUrl` (string): URL to the JavaScript bundle file (e.g., `/assets/main.js` or `/js/app.bundle.js`)
- `expectedHash` (string): Expected SHA-256 hash of the unmodified bundle

**Returns:** Promise resolving to an object:
```javascript
{
  integrityOk: boolean,      // true if hash matches, false if tampered
  actualHash: string,         // SHA-256 hash of the current bundle
  expectedHash: string,       // The hash you provided
  error?: string              // Error message if hash couldn't be computed
}
```

**Example:**
```javascript
import { verifyBundleIntegrity } from 'client-trace';

verifyBundleIntegrity('/assets/main.js', 'sha256-abc123def456').then(result => {
  if (!result.integrityOk) {
    console.error('ALERT: Bundle has been modified!');
    console.error('Expected:', result.expectedHash);
    console.error('Actual:', result.actualHash);
    // Consider blocking the app or alerting the user
  } else {
    console.log('Bundle integrity verified ✓');
  }
});
```

---

##### `generateSessionToken(userUniqueId, hashedIp, secret, expiryTime)`

Creates a cryptographically signed token that binds a user to their IP address and user agent, preventing session token reuse across different machines/networks.

**Parameters:**
- `userUniqueId` (string): Unique identifier for the user (e.g., user ID from your system)
- `hashedIp` (string): Server-provided hash of the user's IP (for privacy). Your server should compute this
- `secret` (string): Shared secret between client and server (minimum 32 characters recommended)
- `expiryTime` (number, optional): Token expiration time in milliseconds from now (default: 1 hour)

**Returns:** Promise resolving to an object:
```javascript
{
  token: string,              // Signed JWT-like token
  signature: string,          // HMAC-SHA256 signature
  issuedAt: number,           // Timestamp when token was created
  expiresAt: number,          // Timestamp when token expires
  userUniqueId: string,       // The user ID encoded in the token
  metadata: object            // Additional claims (IP, UA, etc.)
}
```

**Example:**
```javascript
import { generateSessionToken } from 'client-trace';

const token = await generateSessionToken(
  'user-456',
  'hash-of-ip-from-server',
  'your-secure-shared-secret-32chars',
  3600000  // 1 hour
);

// Send this token with API requests
fetch('/api/secure-endpoint', {
  headers: {
    'X-Session-Token': token.token
  }
});

console.log('Token expires at:', new Date(token.expiresAt));
```

---

#### 2. Network Tampering Detection

##### `detectNetworkAPITampering()`

Checks if the native `fetch` and `XHR` (XMLHttpRequest) APIs have been monkey-patched or replaced, which could indicate malicious browser extensions or script injection.

**Parameters:** None

**Returns:** An object:
```javascript
{
  tampered: boolean,                    // true if any tampering detected
  tamperedFunctions: string[],          // List of tampered functions (e.g., ['fetch', 'XMLHttpRequest'])
  fetchIsNative: boolean,               // true if fetch is original
  xhrIsNative: boolean,                 // true if XMLHttpRequest is original
  details: object                       // Detailed analysis of each API
}
```

**Example:**
```javascript
import { detectNetworkAPITampering } from 'client-trace';

const result = detectNetworkAPITampering();

if (result.tampered) {
  console.warn('⚠️ Network APIs have been modified!');
  console.warn('Tampered functions:', result.tamperedFunctions);
  
  if (!result.fetchIsNative) {
    console.warn('fetch has been intercepted - consider blocking requests');
  }
  if (!result.xhrIsNative) {
    console.warn('XMLHttpRequest has been intercepted - consider blocking requests');
  }
  
  // Take defensive action (e.g., stop sending sensitive data)
} else {
  console.log('Network APIs are clean ✓');
}
```

---

##### `detectProxy(pingUrl)`

Detects if the user is behind a proxy or VPN by analyzing response headers (like `X-Forwarded-For`, `CF-Connecting-IP`) and measuring latency anomalies.

**Parameters:**
- `pingUrl` (string): URL endpoint on your server to ping for latency testing (e.g., `/api/ping`)

**Returns:** Promise resolving to an object:
```javascript
{
  proxyDetected: boolean,                // true if proxy/VPN indicators found
  confidence: number,                    // 0-1 score indicating likelihood
  indicators: string[],                  // List of detected proxy signs (e.g., ['x-forwarded-for', 'unusual-latency'])
  headerAnalysis: object,                // Proxy-related headers detected
  latencyMs: number,                     // Round-trip latency to ping endpoint
  isHighLatency: boolean,                // true if latency exceeds threshold
  details: object                        // Full analysis
}
```

**Example:**
```javascript
import { detectProxy } from 'client-trace';

const proxyCheck = await detectProxy('/api/ping');

console.log('Latency:', proxyCheck.latencyMs, 'ms');
console.log('High latency:', proxyCheck.isHighLatency);

if (proxyCheck.proxyDetected) {
  console.warn(`Proxy/VPN detected with ${(proxyCheck.confidence * 100).toFixed(0)}% confidence`);
  console.warn('Indicators:', proxyCheck.indicators);
  
  // Optional: apply stricter security measures
  if (proxyCheck.confidence > 0.8) {
    console.warn('High confidence proxy detected - consider additional verification');
  }
} else {
  console.log('No proxy detected ✓');
}
```

---

##### `detectTimingAnomalies(options)`

Measures DNS lookup time, TTFB (Time To First Byte), and total request time to detect Man-in-the-Middle (MITM) attacks or unusual network conditions.

**Parameters:**
- `options` (object, optional):
  - `testUrl` (string): URL to test (default: `/api/ping`)
  - `iterations` (number): Number of requests to measure (default: 5)
  - `thresholdMs` (number): Latency threshold in milliseconds (default: 1000)

**Returns:** Promise resolving to an object:
```javascript
{
  anomalyDetected: boolean,              // true if timing is abnormal
  averageLatencyMs: number,              // Average latency across all requests
  minLatencyMs: number,                  // Minimum latency observed
  maxLatencyMs: number,                  // Maximum latency observed
  variance: number,                      // Variance in latencies (high = inconsistent)
  outliers: number[],                    // Individual latencies that are outliers
  isConsistent: boolean,                 // true if latencies are consistent
  mitmLikely: boolean                    // true if MITM attack indicators present
}
```

**Example:**
```javascript
import { detectTimingAnomalies } from 'client-trace';

const timingReport = await detectTimingAnomalies({
  testUrl: '/api/ping',
  iterations: 10,
  thresholdMs: 1500
});

console.log('Average latency:', timingReport.averageLatencyMs, 'ms');

if (timingReport.anomalyDetected) {
  console.warn('⚠️ Timing anomalies detected!');
  console.warn('MITM likely:', timingReport.mitmLikely);
  console.warn('Variance:', timingReport.variance, '(high = inconsistent)');
  
  if (timingReport.mitmLikely) {
    // Consider enhanced security measures
  }
}
```

---

#### 3. Device Fingerprinting

##### `getDeviceFingerprint()`

Generates a lightweight, privacy-friendly fingerprint of the user's device by hashing non-unique signals like screen resolution, OS, timezone, and browser capabilities.

**Parameters:** None

**Returns:** Promise resolving to an object:
```javascript
{
  fingerprintHash: string,               // SHA-256 hash of all fingerprint components
  components: {
    screenResolution: string,            // e.g., "1920x1080"
    colorDepth: number,                  // e.g., 24
    timezone: string,                    // e.g., "UTC-5"
    language: string,                    // Browser language, e.g., "en-US"
    platform: string,                    // e.g., "Win32", "MacIntel"
    hardwareConcurrency: number,         // Number of CPU cores
    deviceMemory: number,                // RAM in GB (approximate)
    canvasFingerprint: string,           // Hash of canvas rendering capabilities
    webglRenderer: string                // GPU renderer info
  },
  stability: number                      // 0-1: likelihood fingerprint stays same over time
}
```

**Example:**
```javascript
import { getDeviceFingerprint } from 'client-trace';

const fingerprint = await getDeviceFingerprint();

console.log('Device fingerprint:', fingerprint.fingerprintHash);
console.log('Screen resolution:', fingerprint.components.screenResolution);
console.log('CPU cores:', fingerprint.components.hardwareConcurrency);
console.log('Fingerprint stability:', fingerprint.stability); // Higher = more stable

// Store for session tracking (not for device tracking across days)
sessionStorage.setItem('deviceId', fingerprint.fingerprintHash);

// Can be sent to server for additional analysis
fetch('/api/telemetry', {
  method: 'POST',
  body: JSON.stringify({ fingerprint: fingerprint.fingerprintHash })
});
```

---

#### 4. Bot Detection

##### `startBehaviorMonitoring()`

Initiates tracking of user behavior signals (mouse movements, click patterns, keyboard activity) in the background. **Call this as early as possible** in your page lifecycle (e.g., in a script tag in `<head>`).

**Parameters:** None

**Returns:** void

**Example:**
```javascript
import { startBehaviorMonitoring } from 'client-trace';

// Call immediately on page load
startBehaviorMonitoring();
console.log('Behavior monitoring started');
```

---

##### `detectBot()`

Analyzes collected behavior data to detect if the current user is likely a bot or headless browser.

**Parameters:** None

**Returns:** An object:
```javascript
{
  botLikely: boolean,                    // true if bot-like behavior detected
  confidence: number,                    // 0-1: how confident we are
  signals: {
    mouseEntropy: number,                // Randomness of mouse movements (low = bot-like)
    rapidClickCount: number,             // Number of unnaturally rapid clicks
    hasMouseMovement: boolean,            // true if any mouse movement detected
    hasClickActivity: boolean,            // true if any clicks detected
    hasKeyboardActivity: boolean,         // true if any keyboard input detected
    headlessBrowserIndicators: boolean,  // true if running in headless browser
    screenTouchCapable: boolean           // true if device has touch screen
  },
  botScore: number                       // 0-1: overall bot likelihood score
}
```

**Example:**
```javascript
import { startBehaviorMonitoring, detectBot } from 'client-trace';

// On page load
startBehaviorMonitoring();

// Later, before a sensitive action (e.g., form submission)
document.getElementById('submitBtn').addEventListener('click', () => {
  const botCheck = detectBot();
  
  console.log('Bot likelihood:', (botCheck.botScore * 100).toFixed(0) + '%');
  
  if (botCheck.botLikely) {
    console.warn('🤖 Bot-like behavior detected!', botCheck.signals);
    
    // Options:
    // 1. Show CAPTCHA
    // 2. Block submission
    // 3. Send to server for additional verification
    if (botCheck.confidence > 0.9) {
      alert('Please complete a CAPTCHA to continue');
      return;
    }
  }
  
  // Proceed with form submission
  console.log('Behavior looks human ✓');
});

// Additional signal details
console.log('Mouse entropy:', botCheck.signals.mouseEntropy, '(0=none, 1=highly random)');
console.log('Rapid clicks:', botCheck.signals.rapidClickCount);
console.log('Headless browser:', botCheck.signals.headlessBrowserIndicators);
```

---

#### 5. Security Monitoring

##### `detectInjections()`

Monitors the DOM for unexpected `<script>` tags that could indicate malicious script injection or XSS attacks.

**Parameters:** None

**Returns:** An object:
```javascript
{
  injectionsDetected: boolean,           // true if unknown scripts found
  injectedScripts: Array<{
    src: string,                         // Script URL or 'inline'
    trusted: boolean,                    // false if not in whitelist
    timestamp: number                    // When detected
  }>,
  trustedScripts: string[],              // Scripts you've whitelisted
  recommendations: string[]              // Suggested actions
}
```

**Example:**
```javascript
import { detectInjections } from 'client-trace';

const injectionReport = detectInjections();

if (injectionReport.injectionsDetected) {
  console.error('⚠️ Potential script injection detected!');
  injectionReport.injectedScripts.forEach(script => {
    console.error(`Untrusted script: ${script.src}`);
  });
  
  // Alert the user or server
  fetch('/api/security-alert', {
    method: 'POST',
    body: JSON.stringify({ 
      type: 'script-injection',
      scripts: injectionReport.injectedScripts
    })
  });
} else {
  console.log('No unauthorized scripts detected ✓');
}
```

---

##### `listenForCSPViolations(onViolation)`

Listens for Content Security Policy (CSP) violation events and calls a callback whenever a violation occurs.

**Parameters:**
- `onViolation` (function): Callback function that receives violation details

**Returns:** An object:
```javascript
{
  isListening: boolean,                  // true if listener is active
  violationCount: number,                // Total violations captured
  stopListening: function,               // Call to remove the listener
  violations: Array<{
    blockedUri: string,
    violatedDirective: string,           // e.g., 'script-src'
    originalPolicy: string,
    timestamp: number
  }>
}
```

**Example:**
```javascript
import { listenForCSPViolations } from 'client-trace';

const cspListener = listenForCSPViolations((violation) => {
  console.warn('CSP Violation detected:');
  console.warn(`  Blocked URI: ${violation.blockedUri}`);
  console.warn(`  Directive: ${violation.violatedDirective}`);
  
  // Send to your server for analysis
  fetch('/api/csp-violations', {
    method: 'POST',
    body: JSON.stringify(violation)
  });
});

console.log('CSP violations are being monitored');

// Later, if you want to stop listening:
// cspListener.stopListening();
```

---

##### `checkStorageIntegrity(storageType, checkInterval)`

Verifies that `localStorage` or `sessionStorage` hasn't been modified externally (e.g., by browser extensions or other tabs).

**Parameters:**
- `storageType` (string): Either `'local'` or `'session'` (default: `'local'`)
- `checkInterval` (number): How often to check in milliseconds (default: 5000)

**Returns:** An object:
```javascript
{
  isIntact: boolean,                     // true if storage hasn't been tampered with
  tamperedKeys: string[],                // Keys that have been modified
  addedKeys: string[],                   // Keys that were added externally
  removedKeys: string[],                 // Keys that were removed externally
  stopMonitoring: function,              // Call to stop integrity checks
  lastCheckTime: number                  // Timestamp of last check
}
```

**Example:**
```javascript
import { checkStorageIntegrity } from 'client-trace';

// Start monitoring localStorage
const storageCheck = checkStorageIntegrity('local', 3000);

if (!storageCheck.isIntact) {
  console.error('⚠️ Local storage has been tampered with!');
  console.error('Tampered keys:', storageCheck.tamperedKeys);
  console.error('Added keys:', storageCheck.addedKeys);
  
  // Clear potentially compromised data
  localStorage.clear();
  
  // Alert server
  fetch('/api/security-alert', {
    method: 'POST',
    body: JSON.stringify({
      type: 'storage-tampering',
      tamperedKeys: storageCheck.tamperedKeys
    })
  });
}

// Stop monitoring when done
// storageCheck.stopMonitoring();
```

---

#### 6. Secure Transport

##### `signPayload(payload, secret)`

Signs a data payload using HMAC-SHA256 to ensure authenticity and prevent tampering in transit.

**Parameters:**
- `payload` (object or string): Data to sign
- `secret` (string): Shared secret (minimum 32 characters recommended)

**Returns:** Promise resolving to an object:
```javascript
{
  payload: any,                          // The original payload
  signature: string,                     // HMAC-SHA256 signature (hex)
  algorithm: string,                     // Always "HMAC-SHA256"
  timestamp: number                      // When signed
}
```

**Example:**
```javascript
import { signPayload } from 'client-trace';

const data = {
  userId: '12345',
  action: 'login',
  timestamp: Date.now()
};

const signed = await signPayload(data, 'your-shared-secret-key');

console.log('Payload:', signed.payload);
console.log('Signature:', signed.signature);

// Send both payload and signature to server
fetch('/api/secure-action', {
  method: 'POST',
  body: JSON.stringify(signed),
  headers: { 'Content-Type': 'application/json' }
});

// Server-side: verify using the same secret
// Server should recompute: HMAC-SHA256(payload, secret)
// and compare with received signature
```

---

##### `encryptTelemetry(payload, secret)`

Encrypts sensitive telemetry data using AES-256-GCM encryption for end-to-end security.

**Parameters:**
- `payload` (object): Data to encrypt
- `secret` (string): Encryption key (minimum 32 characters)

**Returns:** Promise resolving to an object:
```javascript
{
  encrypted: string,                     // Encrypted payload (base64)
  iv: string,                            // Initialization vector (base64)
  authTag: string,                       // Authentication tag for integrity (base64)
  algorithm: string,                     // "AES-256-GCM"
  nonce: string,                         // Replay protection nonce
  timestamp: number                      // When encrypted
}
```

**Example:**
```javascript
import { encryptTelemetry } from 'client-trace';

const telemetry = {
  event: 'user-action',
  userId: 'user-123',
  ipAddress: '192.168.1.1',
  sessionId: 'sess-456'
};

const encrypted = await encryptTelemetry(telemetry, 'your-shared-secret-key');

console.log('Encrypted payload:', encrypted.encrypted);
console.log('IV:', encrypted.iv);
console.log('Auth tag:', encrypted.authTag);

// Send encrypted data to server
fetch('/api/telemetry', {
  method: 'POST',
  body: JSON.stringify({
    data: encrypted.encrypted,
    iv: encrypted.iv,
    authTag: encrypted.authTag,
    nonce: encrypted.nonce
  })
});

// Server-side decryption:
// 1. Get IV, authTag, and nonce from request
// 2. Verify nonce hasn't been used before (replay protection)
// 3. Decrypt using: decipher.update(encrypted, 'base64') + decipher.final()
// 4. Verify auth tag
```

---

##### `decryptTelemetry(encrypted, iv, authTag, secret)`

Decrypts telemetry data that was encrypted with `encryptTelemetry`.

**Parameters:**
- `encrypted` (string): Encrypted payload (base64)
- `iv` (string): Initialization vector from encryption (base64)
- `authTag` (string): Authentication tag from encryption (base64)
- `secret` (string): Same secret used during encryption

**Returns:** Promise resolving to an object:
```javascript
{
  decrypted: object,                     // Original decrypted payload
  verified: boolean,                     // true if auth tag is valid
  algorithm: string                      // "AES-256-GCM"
}
```

**Example:**
```javascript
import { decryptTelemetry } from 'client-trace';

// Assuming server sent back encrypted data
const response = await fetch('/api/telemetry/config');
const { data, iv, authTag } = await response.json();

const decrypted = await decryptTelemetry(data, iv, authTag, 'your-shared-secret-key');

if (decrypted.verified) {
  console.log('Decrypted config:', decrypted.decrypted);
  console.log('Integrity verified ✓');
  
  // Use the decrypted configuration
  applyConfig(decrypted.decrypted);
} else {
  console.error('Authentication tag verification failed!');
  console.error('Data may have been tampered with');
}
```

---

##### `getNonce()`

Generates a unique, rotating nonce for replay protection. Each call returns a new nonce that can be validated on the server to ensure requests aren't replayed.

**Parameters:** None

**Returns:** An object:
```javascript
{
  nonce: string,                         // Unique nonce value (hex)
  timestamp: number,                     // When nonce was generated
  expiresAt: number,                     // When nonce becomes invalid (10 minutes)
  isValid: boolean                       // true if nonce hasn't expired
}
```

**Example:**
```javascript
import { getNonce } from 'client-trace';

// Before making a sensitive API request
const nonce = getNonce();

fetch('/api/sensitive-action', {
  method: 'POST',
  headers: {
    'X-Nonce': nonce.nonce
  },
  body: JSON.stringify({
    action: 'transfer-funds',
    amount: 100
  })
});

// Server-side:
// 1. Check if nonce has been used before (in a cache/database)
// 2. Verify nonce hasn't expired
// 3. Mark nonce as "used"
// 4. Proceed with action only if nonce is valid and unused

// Client-side error handling:
if (!nonce.isValid) {
  console.error('Nonce has expired - get a new one');
}

console.log('Nonce expires in:', Math.round((nonce.expiresAt - Date.now()) / 1000), 'seconds');
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

---

## Contributing

Contributions are welcome!
Feel free to open issues for bugs, feature requests, or documentation improvements.

If you’d like to contribute code:
1. Fork the repository
2. Create a new branch
3. Make your changes
4. Open a pull request

## Development

```bash
npm install
npm run build
npm test
```
