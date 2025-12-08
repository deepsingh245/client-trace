const express = require('express');
const path = require('path');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const app = express();
const port = 3000;

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.text()); // For CSP reports or raw text if needed

// Serve the entire project root so /test/index.html and /src imports work
app.use(express.static(path.join(__dirname, '../../')));

// ============================================
// INTEGRITY ENDPOINTS
// ============================================

// Serve a specific JS file content for hashing (simulated bundle)
app.get('/api/integrity/bundle', (req, res) => {
    // Return a fixed script content
    const scriptContent = 'console.log("This is the bundle content to verify.");';
    res.setHeader('Content-Type', 'application/javascript');
    res.send(scriptContent);
});

// ============================================
// AUTH / SESSION ENDPOINTS
// ============================================

app.post('/api/auth/session', (req, res) => {
    const { userId, ipHash, secret } = req.body;

    if (!userId || !ipHash || !secret) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    // Simulate token generation
    // In a real app, this would be a JWT or similar signed token
    const rawData = `${userId}:${ipHash}:${Date.now()}`;
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(rawData);
    const token = hmac.digest('hex');

    res.json({
        token: `session-${token}`,
        userId,
        expiresIn: 3600,
        context: {
            ipHashResolved: ipHash
        }
    });
});

// ============================================
// NETWORK ENDPOINTS
// ============================================

app.get('/api/network/detect-proxy', (req, res) => {
    const headers = req.headers;
    const proxyHeaders = [
        'via',
        'x-forwarded-for',
        'forwarded',
        'proxy-connection',
        'x-proxy-id'
    ];

    const detected = proxyHeaders.filter(h => headers[h] !== undefined);

    // Also check for specific suspicious values if needed

    res.json({
        proxyLikely: detected.length > 0,
        detectedHeaders: detected,
        clientIp: req.socket.remoteAddress
    });
});

app.get('/api/network/timing', (req, res) => {
    // Simulate server processing time to help client calculate RTT
    // We intentionally delay a bit to simulate "processing"
    setTimeout(() => {
        res.json({
            serverTime: Date.now(),
            status: 'ok'
        });
    }, 100);
});

// ============================================
// FINGERPRINTING & BOT ENDPOINTS
// ============================================

app.post('/api/fingerprint', (req, res) => {
    const fingerprintData = req.body;

    console.log('Received Fingerprint:', fingerprintData);

    // In a real app, we would store this and check for duplicates or anomalies
    res.json({
        status: 'recorded',
        fingerprintId: crypto.createHash('sha256').update(JSON.stringify(fingerprintData)).digest('hex').substring(0, 12),
        riskScore: 0.1 // Low risk simulated
    });
});

app.post('/api/bot-detection', (req, res) => {
    const behaviorData = req.body; // e.g., mouse movements, clicks

    // Simple heuristic: if no events, maybe bot?
    const eventCount = behaviorData.events ? behaviorData.events.length : 0;
    const botLikely = eventCount < 5; // Arbitrary threshold for demo

    res.json({
        botLikely,
        analysis: botLikely ? 'Too few interactions detected.' : 'Human-like behavior detected.',
        confidence: 0.85
    });
});

// ============================================
// SECURITY ENDPOINTS
// ============================================

app.post('/api/csp-report', (req, res) => {
    console.warn('CSP Violation Reported:', req.body);
    // Usually standard CSP reports are JSON, sometimes generic content-type
    res.status(204).end();
});

// ============================================
// TRANSPORT ENDPOINTS
// ============================================

app.post('/api/transport/verify-signature', (req, res) => {
    const { payload, signature, secret } = req.body;

    if (!payload || !signature || !secret) {
        return res.status(400).json({ error: 'Missing data' });
    }

    // Verify HMAC
    // Assuming payload is passed as a string or object that was stringified for signing
    // For simplicity, let's assume client sends the raw object and we modify it same way? 
    // Or client sends the content it signed.

    // Let's assume 'payload' in body IS the data content
    const content = typeof payload === 'string' ? payload : JSON.stringify(payload);

    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(content);
    const expectedSignature = hmac.digest('hex');

    if (crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) {
        res.json({ valid: true, message: 'Signature matches' });
    } else {
        res.json({ valid: false, message: 'Signature mismatch' });
    }
});

app.post('/api/transport/decrypt', (req, res) => {
    const { encryptedData, iv, secret } = req.body;

    if (!encryptedData || !iv || !secret) {
        return res.status(400).json({ error: 'Missing encryption data' });
    }

    try {
        // Derive key from secret (simple hash to get 32 bytes for AES-256)
        const key = crypto.createHash('sha256').update(secret).digest();

        const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));

        // In GCM, auth tag is usually appended or sent separately.
        // If client-trace sends it separately, we need it. 
        // Let's assume standard auth tag handling if present, or maybe just simple AES-CBC/GCM depending on SDK.
        // Looking at the prompt, it just says encrypt/decrypt. 
        // Let's assume standard format: IV + Encrypted + AuthTag if GCM used?

        // If the SDK uses a specific format, we might need to adjust. 
        // For now, let's implement a generic decryption assuming standard node crypto usage.
        // We'll extract AuthTag if it's passed, otherwise assume it's part of data or not using GCM auth check in this simple demo.
        // Wait, GCM *requires* auth tag for `setAuthTag`.

        // Let's check `req.body.authTag`
        if (req.body.authTag) {
            decipher.setAuthTag(Buffer.from(req.body.authTag, 'hex'));
        }

        let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        res.json({ success: true, decrypted: JSON.parse(decrypted) });
    } catch (err) {
        console.error('Decryption failed:', err);
        res.status(500).json({ success: false, error: 'Decryption failed' });
    }
});


app.listen(port, () => {
    console.log(`Test backend running at http://localhost:${port}`);
});
