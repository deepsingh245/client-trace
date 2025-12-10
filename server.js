import { createServer } from 'http';
import { createHmac } from 'crypto';

const PORT = process.env.PORT || 5000;

function parseBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => {
            try {
                resolve(body ? JSON.parse(body) : {});
            } catch (e) {
                reject(e);
            }
        });
        req.on('error', reject);
    });
}

const server = createServer(async (req, res) => {
    // --- CORS ---
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, HEAD, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    const url = new URL(req.url, `https://${req.headers.host}`);
    const pathname = url.pathname;

    console.log(`${req.method} ${pathname}`);

    // --- API Endpoints ---

    // 1. Integrity: Serve Mock Bundle
    if (pathname === '/api/integrity/bundle') {
        res.writeHead(200, { 'Content-Type': 'text/javascript' });
        res.end("console.log('Valid Bundle');");
        return;
    }

    // 1b. Integrity: Serve Tampered Bundle
    if (pathname === '/api/integrity/bundle-tampered') {
        res.writeHead(200, { 'Content-Type': 'text/javascript' });
        res.end("console.log('Valid Bundle');\n// TAMPERED CODE DETECTED");
        return;
    }

    // 2. Auth: Session Token
    if (pathname === '/api/auth/session' && req.method === 'POST') {
        try {
            const { userId, ipHash, secret } = await parseBody(req);

            const expiry = Date.now() + 3600000;

            const b64 = str => Buffer.from(String(str)).toString('base64');
            const dataToSign = `${b64(userId)}.${b64(ipHash)}.${b64(expiry)}`;

            const hmac = createHmac('sha256', secret);
            hmac.update(dataToSign);

            const signature = hmac.digest('hex');
            const token = `${dataToSign}.${signature}`;

            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ token, expiry }));
        } catch (err) {
            res.statusCode = 400;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ error: err.message }));
        }
        return;
    }

    // 3. Network: Proxy Detection
    if (pathname === '/api/network/detect-proxy') {
        const headers = { ...req.headers };

        // Clean up internal node headers
        delete headers.host;
        delete headers.connection;

        // Check for simulation flag
        if (url.searchParams.get('simulate') === 'true') {
            headers['via'] = '1.1 example-proxy';
            headers['x-forwarded-for'] = '203.0.113.195';
            headers['x-proxy-id'] = 'proxy-123';
        }

        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Access-Control-Expose-Headers', 'via, x-forwarded-for, x-proxy-id');

        // Add proxy headers
        if (headers['via']) res.setHeader('via', headers['via']);
        if (headers['x-forwarded-for']) res.setHeader('x-forwarded-for', headers['x-forwarded-for']);
        if (headers['x-proxy-id']) res.setHeader('x-proxy-id', headers['x-proxy-id']);

        res.end(JSON.stringify({ message: 'Proxy headers sent' }));
        return;
    }

    // 4. Network: Timing
    if (pathname === '/api/network/timing') {
        // Artificial delay for testing?
        // setTimeout(() => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ timestamp: Date.now() }));
        // }, 100);
        return;
    }

    // 5. Fingerprint
    if (pathname === '/api/fingerprint' && req.method === 'POST') {
        const data = await parseBody(req);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ received: true, serverTime: Date.now(), fingerprintHash: data.fingerprintHash }));
        return;
    }

    // 6. Bot Detection
    if (pathname === '/api/bot-detection' && req.method === 'POST') {
        const body = await parseBody(req);
        const { result } = body;

        // Simple server-side "logic"
        let verdict = 'human';
        if (result && result.botLikely) verdict = 'bot';

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ verdict, analysis: 'Server concurs with client assessment' }));
        return;
    }

    // 7. CSP Report
    if (pathname === '/api/csp-report') {
        // CSP reports might be sent with application/csp-report content type
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', () => {
            console.log('CSP Violation Received:', body);
            res.writeHead(204);
            res.end();
        });
        return;
    }

    // 8. Transport: Verify Signature
    if (pathname === '/api/transport/verify-signature' && req.method === 'POST') {
        try {
            const { payload, signature, secret } = await parseBody(req);

            // Re-calculate signature
            // Client likely JSON.stringifies the payload.
            // CAUTION: JSON.stringify order is not guaranteed, but for simple tests usually fine.
            // Ideally client sends the exact raw string it signed.
            const payloadStr = JSON.stringify(payload);

            const hmac = createHmac('sha256', secret);
            hmac.update(payloadStr);
            const expectedSig = hmac.digest('hex');

            const isValid = (signature === expectedSig);

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ isValid, serverDerivedSignature: expectedSig }));
        } catch (e) {
            res.writeHead(400); res.end(JSON.stringify({ error: e.message }));
        }
        return;
    }

    // 9. Transport: Decrypt
    if (pathname === '/api/transport/decrypt' && req.method === 'POST') {
        try {
            const { encryptedData, iv, authTag, secret } = await parseBody(req);

            // Assuming encryptedData is an object with 'ciphertext', 'iv', 'authTag'
            const { ciphertext, iv: ivBase64, authTag: authTagBase64, salt: saltBase64 } = encryptedData;

            // Decode base64 inputs
            const ivBuf = Buffer.from(ivBase64, 'base64');
            const ciphertextBuf = Buffer.from(ciphertext, 'base64');
            const authTagBuf = Buffer.from(authTagBase64, 'base64');
            const saltBuf = Buffer.from(saltBase64, 'base64');

            // Derive key from the secret and salt (same method as client-side)
            const keyBuffer = await deriveKey(secret, saltBuf);

            const decipher = createDecipheriv('aes-256-gcm', keyBuffer, ivBuf);
            decipher.setAuthTag(authTagBuf);

            // Decrypt the ciphertext
            let decrypted = decipher.update(ciphertextBuf, undefined, 'utf8');
            decrypted += decipher.final('utf8');  // This can throw if authentication fails

            // Try parsing decrypted data as JSON
            try {
                const parsedDecryptedData = JSON.parse(decrypted);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(parsedDecryptedData));
            } catch (e) {
                console.error('Decryption succeeded but JSON parsing failed:', e);
                res.writeHead(400);
                res.end(JSON.stringify({ error: 'Decrypted data is not valid JSON', details: e.message }));
            }
        } catch (e) {
            console.error('Decryption failed:', e);
            res.writeHead(400);
            res.end(JSON.stringify({ error: 'Decryption failed', details: e.message }));
        }
        return;
    }

    /**
     * Derives an AES-GCM key from a shared secret using PBKDF2 (same method used on the client side).
     * @param {string} secret - The shared secret.
     * @param {Buffer} salt - The salt (must match the client-side salt).
     * @returns {Promise<Buffer>}
     */
    async function deriveKey(secret, salt) {
        return new Promise((resolve, reject) => {
            pbkdf2(secret, salt, 100000, 32, 'sha256', (err, derivedKey) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(derivedKey);
                }
            });
        });
    }

    // --- Fallback ---

    res.writeHead(404);
    res.end('Not Found');
});

server.listen(PORT, () => {
    console.log(`Test server running at http://localhost:${PORT}/`);
});
