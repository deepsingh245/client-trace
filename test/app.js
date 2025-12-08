// Import all modules from the library
import * as ClientTrace from '../src/index.js';

const BACKEND_URL = 'http://localhost:3000';

// Helper function to display results
function displayResult(elementId, data, type = 'success') {
    const element = document.getElementById(elementId);
    element.textContent = JSON.stringify(data, null, 2);
    element.className = `result show ${type}`;
}

// ============================================
// INTEGRITY TESTS
// ============================================

// Test Bundle Integrity
document.getElementById('test-bundle-integrity').addEventListener('click', async () => {
    try {
        // For demo purposes, we'll check the app.js file itself
        // Check the dummy bundle from our backend
        const result = await ClientTrace.verifyBundleIntegrity(
            `${BACKEND_URL}/api/integrity/bundle`,
            'fakehash123' // This will fail intentionally, or we can update to real hash later
        );
        displayResult('result-bundle-integrity', result, result.integrityOk ? 'success' : 'warning');
    } catch (error) {
        displayResult('result-bundle-integrity', { error: error.message }, 'error');
    }
});

// Test Session Token
document.getElementById('test-session-token').addEventListener('click', async () => {
    try {
        const userId = document.getElementById('user-id').value;
        const ipHash = document.getElementById('ip-hash').value;
        const secret = document.getElementById('secret-key').value;

        // In a real scenario, the server generates the token.
        // We will call our backend to do this.
        const response = await fetch(`${BACKEND_URL}/api/auth/session`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ userId, ipHash, secret })
        });

        const data = await response.json();

        if (!response.ok) throw new Error(data.error || 'Failed to generate token');

        displayResult('result-session-token', data, 'success');
    } catch (error) {
        displayResult('result-session-token', { error: error.message }, 'error');
    }
});

// ============================================
// NETWORK TESTS
// ============================================

// Simulate network tampering
document.getElementById('simulate-tamper').addEventListener('click', () => {
    // Monkey-patch fetch
    window.fetch = function () {
        return Promise.resolve({ ok: true });
    };
    displayResult('result-tamper', { message: 'fetch has been monkey-patched!' }, 'warning');
});

// Detect network tampering
document.getElementById('detect-tamper').addEventListener('click', () => {
    const result = ClientTrace.detectNetworkAPITampering();
    displayResult('result-tamper', result, result.tampered ? 'error' : 'success');
});

// Test Proxy Detection
document.getElementById('test-proxy').addEventListener('click', async () => {
    try {
        // Use the backend endpoint for proxy detection
        const result = await ClientTrace.detectProxy(`${BACKEND_URL}/api/network/detect-proxy`);
        displayResult('result-proxy', result, result.proxyLikely ? 'warning' : 'success');
    } catch (error) {
        displayResult('result-proxy', { error: error.message }, 'error');
    }
});

// Test Timing Anomalies
document.getElementById('test-timing').addEventListener('click', async () => {
    try {
        // Test against current origin
        const result = await ClientTrace.detectTimingAnomalies(`${BACKEND_URL}/api/network/timing`);
        displayResult('result-timing', result, result.anomaly ? 'warning' : 'success');
    } catch (error) {
        displayResult('result-timing', { error: error.message }, 'error');
    }
});

// ============================================
// FINGERPRINTING & BEHAVIOR TESTS
// ============================================

// Test Device Fingerprint
document.getElementById('test-fingerprint').addEventListener('click', async () => {
    try {
        const result = await ClientTrace.getDeviceFingerprint();

        // Send fingerprint to backend
        const serverResponse = await fetch(`${BACKEND_URL}/api/fingerprint`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(result)
        });
        const serverData = await serverResponse.json();

        displayResult('result-fingerprint', { client: result, server: serverData }, 'success');
    } catch (error) {
        displayResult('result-fingerprint', { error: error.message }, 'error');
    }
});

// Start behavior monitoring
document.getElementById('start-monitor').addEventListener('click', () => {
    ClientTrace.startBehaviorMonitoring();
    displayResult('result-bot', { message: 'Behavior monitoring started. Move your mouse and click around!' }, 'success');
});

// Stop behavior monitoring
document.getElementById('stop-monitor').addEventListener('click', () => {
    ClientTrace.stopBehaviorMonitoring();
    displayResult('result-bot', { message: 'Behavior monitoring stopped.' }, 'success');
});

// Test Bot Detection
document.getElementById('test-bot').addEventListener('click', () => {
    const result = ClientTrace.detectBot();

    // Simulate sending behavior data to backend
    fetch(`${BACKEND_URL}/api/bot-detection`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            result,
            events: window.ClientTraceBehaviorEvents || [] // Assuming library exposes this or we simulate
        })
    })
        .then(res => res.json())
        .then(serverData => {
            displayResult('result-bot', { client: result, server: serverData }, result.botLikely ? 'warning' : 'success');
        })
        .catch(err => displayResult('result-bot', { error: err.message }, 'error'));
});

// ============================================
// SECURITY TESTS
// ============================================

// Inject a test script
document.getElementById('inject-script').addEventListener('click', () => {
    const script = document.createElement('script');
    script.src = 'https://example.com/malicious.js';
    document.body.appendChild(script);
    displayResult('result-injection', { message: 'Test script injected into DOM!' }, 'warning');
});

// Detect script injection
document.getElementById('detect-injection').addEventListener('click', () => {
    const result = ClientTrace.detectInjections();
    displayResult('result-injection', result, result.extensionSuspected ? 'warning' : 'success');
});

// Start CSP listener
document.getElementById('start-csp').addEventListener('click', () => {
    ClientTrace.listenForCSPViolations((violation) => {
        displayResult('result-csp', violation, 'warning');
        // Report to backend
        fetch(`${BACKEND_URL}/api/csp-report`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/csp-report' }, // Standard MIME type often used
            body: JSON.stringify(violation)
        }).catch(console.error);
    });
    displayResult('result-csp', { message: 'CSP listener started. Violations will be sent to backend.' }, 'success');
});

// Initialize storage monitoring
document.getElementById('init-storage').addEventListener('click', async () => {
    localStorage.setItem('test-key-1', 'test-value-1');
    localStorage.setItem('test-key-2', 'test-value-2');
    await ClientTrace.monitorStorage(['test-key-1', 'test-key-2']);
    displayResult('result-storage', { message: 'Storage initialized and monitoring started for test-key-1 and test-key-2' }, 'success');
});

// Tamper with storage
document.getElementById('tamper-storage').addEventListener('click', () => {
    localStorage.setItem('test-key-1', 'TAMPERED VALUE');
    displayResult('result-storage', { message: 'test-key-1 has been tampered!' }, 'warning');
});

// Check storage integrity
document.getElementById('check-storage').addEventListener('click', async () => {
    const result = await ClientTrace.checkStorageIntegrity();
    displayResult('result-storage', result, result.storageTampered ? 'error' : 'success');
});

// ============================================
// TRANSPORT TESTS
// ============================================

// Test Payload Signing
document.getElementById('test-sign').addEventListener('click', async () => {
    try {
        const payloadText = document.getElementById('payload-sign').value;
        const secret = document.getElementById('sign-secret').value;
        const payload = JSON.parse(payloadText);

        const signed = await ClientTrace.signPayload(payload, secret);

        // Verify with backend
        const verifyResponse = await fetch(`${BACKEND_URL}/api/transport/verify-signature`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                payload: signed.payload, // Assuming structure
                signature: signed.signature,
                secret
            })
        });
        const verifyData = await verifyResponse.json();

        displayResult('result-sign', { signed, verification: verifyData }, 'success');
    } catch (error) {
        displayResult('result-sign', { error: error.message }, 'error');
    }
});

// Test Encryption
document.getElementById('test-encrypt').addEventListener('click', async () => {
    try {
        const payloadText = document.getElementById('payload-encrypt').value;
        const secret = document.getElementById('encrypt-secret').value;
        const payload = JSON.parse(payloadText);

        const result = await ClientTrace.encryptTelemetry(payload, secret);

        // Decrypt with backend
        const decryptResponse = await fetch(`${BACKEND_URL}/api/transport/decrypt`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                encryptedData: result.encryptedData || result, // Adjust based on actual SDK output
                iv: result.iv,
                authTag: result.authTag, // If GCM
                secret
            })
        });
        const decryptData = await decryptResponse.json();

        displayResult('result-encrypt', {
            clientEncrypted: result,
            serverDecrypted: decryptData,
            note: 'Backend successfully decrypted the data'
        }, 'success');
    } catch (error) {
        displayResult('result-encrypt', { error: error.message }, 'error');
    }
});

// Test Nonce
document.getElementById('test-nonce').addEventListener('click', () => {
    const result = ClientTrace.getNonce();
    displayResult('result-nonce', result, 'success');
});

// ============================================
// FULL SECURITY REPORT
// ============================================

document.getElementById('test-full-report').addEventListener('click', async () => {
    try {
        displayResult('result-full-report', { message: 'Generating comprehensive security report...' }, 'success');

        const config = {
            pingUrl: window.location.href,
            // Note: bundleUrl and expectedBundleHash are optional for demo
        };

        const report = await ClientTrace.collectSecurityReport(config);
        displayResult('result-full-report', report, 'success');
    } catch (error) {
        displayResult('result-full-report', { error: error.message }, 'error');
    }
});

// Initialize on load
window.addEventListener('load', () => {
    console.log('Client-Trace Test Suite loaded successfully!');
    console.log('Available modules:', Object.keys(ClientTrace));
});
