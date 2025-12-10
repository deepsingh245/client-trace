// server.js
import { createServer } from 'http';
import { createHmac, pbkdf2, createDecipheriv } from 'crypto';

const PORT = process.env.PORT || 5000;

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', () => {
      if (!body) return resolve({});
      // try JSON parse, fallback to raw text
      try {
        resolve(JSON.parse(body));
      } catch (e) {
        // Not JSON — return raw text (so callers can handle)
        resolve(body);
      }
    });
    req.on('error', reject);
  });
}

function setCorsHeaders(res) {
  // You asked for "All" — this sets Access-Control-Allow-Origin to '*'
  // Note: with '*' you cannot use cookies/credentials (Access-Control-Allow-Credentials: true)
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, HEAD, PUT, DELETE');
  // Browsers won't accept '*' for Access-Control-Allow-Headers on preflight; list common headers.
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept');
  // Expose any custom headers you might return
  res.setHeader('Access-Control-Expose-Headers', 'via, x-forwarded-for, x-proxy-id');
  // Help caches/proxies vary responses by Origin — good practice
  res.setHeader('Vary', 'Origin');
}

async function deriveKey(secret, salt) {
  // pbkdf2 callback -> promise wrapper
  return new Promise((resolve, reject) => {
    // 100k iterations, 32 bytes, sha256 (matches your comment)
    pbkdf2(String(secret), salt, 100000, 32, 'sha256', (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
}

const server = createServer(async (req, res) => {
  try {
    // Always set CORS headers first so every response includes them
    setCorsHeaders(res);

    // Handle preflight quickly
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // Safe URL parsing: req.url may be absolute-path. Use a stable base.
    const base = 'http://localhost';
    const url = new URL(req.url || '/', base);
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
        const body = await parseBody(req);
        // body might be raw string if not JSON — guard for that
        const { userId, ipHash, secret } = typeof body === 'object' ? body : {};
        if (!userId || !ipHash || !secret) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Missing userId, ipHash or secret' }));
          return;
        }

        const expiry = Date.now() + 3600000;
        const b64 = str => Buffer.from(String(str)).toString('base64');
        const dataToSign = `${b64(userId)}.${b64(ipHash)}.${b64(expiry)}`;

        const hmac = createHmac('sha256', secret);
        hmac.update(dataToSign);
        const signature = hmac.digest('hex');
        const token = `${dataToSign}.${signature}`;

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ token, expiry }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
      return;
    }

    // 3. Network: Proxy Detection
    if (pathname === '/api/network/detect-proxy') {
      const headers = { ...req.headers };
      delete headers.host;
      delete headers.connection;

      if (url.searchParams.get('simulate') === 'true') {
        headers.via = '1.1 example-proxy';
        headers['x-forwarded-for'] = '203.0.113.195';
        headers['x-proxy-id'] = 'proxy-123';
      }

      // Add proxy headers to response if present
      if (headers.via) res.setHeader('via', headers.via);
      if (headers['x-forwarded-for']) res.setHeader('x-forwarded-for', headers['x-forwarded-for']);
      if (headers['x-proxy-id']) res.setHeader('x-proxy-id', headers['x-proxy-id']);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ message: 'Proxy headers sent' }));
      return;
    }

    // 4. Network: Timing
    if (pathname === '/api/network/timing') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ timestamp: Date.now() }));
      return;
    }

    // 5. Fingerprint
    if (pathname === '/api/fingerprint' && req.method === 'POST') {
      const data = await parseBody(req);
      // accept either JSON object or raw string (if client sends text)
      const fingerprintHash = (typeof data === 'object' && data.fingerprintHash) ? data.fingerprintHash : data;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ received: true, serverTime: Date.now(), fingerprintHash }));
      return;
    }

    // 6. Bot Detection
    if (pathname === '/api/bot-detection' && req.method === 'POST') {
      const body = await parseBody(req);
      const { result } = (typeof body === 'object' ? body : {});
      let verdict = 'human';
      if (result && result.botLikely) verdict = 'bot';
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ verdict, analysis: 'Server concurs with client assessment' }));
      return;
    }

    // 7. CSP Report
    if (pathname === '/api/csp-report') {
      // CSP reports might be sent with application/csp-report
      let body = '';
      req.on('data', chunk => { body += chunk.toString(); });
      req.on('end', () => {
        console.log('CSP Violation Received:', body);
        res.writeHead(204);
        res.end();
      });
      req.on('error', (e) => {
        console.error('CSP report read error', e);
        res.writeHead(400);
        res.end();
      });
      return;
    }

    // 8. Transport: Verify Signature
    if (pathname === '/api/transport/verify-signature' && req.method === 'POST') {
      try {
        const body = await parseBody(req);
        const { payload, signature, secret } = (typeof body === 'object' ? body : {});
        if (typeof payload === 'undefined' || !signature || !secret) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Missing payload, signature or secret' }));
          return;
        }

        const payloadStr = JSON.stringify(payload);
        const hmac = createHmac('sha256', secret);
        hmac.update(payloadStr);
        const expectedSig = hmac.digest('hex');
        const isValid = signature === expectedSig;

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ isValid, serverDerivedSignature: expectedSig }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
      return;
    }

    // 9. Transport: Decrypt
    if (pathname === '/api/transport/decrypt' && req.method === 'POST') {
      try {
        const body = await parseBody(req);
        // Expect an object like { encryptedData: { ciphertext, iv, authTag, salt }, secret }
        const encryptedData = (typeof body === 'object' ? body.encryptedData : undefined);
        const secret = (typeof body === 'object' ? body.secret : undefined);

        if (!encryptedData || !secret) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Missing encryptedData or secret' }));
          return;
        }

        const { ciphertext, iv: ivBase64, authTag: authTagBase64, salt: saltBase64 } = encryptedData;

        if (!ciphertext || !ivBase64 || !authTagBase64 || !saltBase64) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'encryptedData missing ciphertext/iv/authTag/salt' }));
          return;
        }

        const ivBuf = Buffer.from(ivBase64, 'base64');
        const ciphertextBuf = Buffer.from(ciphertext, 'base64');
        const authTagBuf = Buffer.from(authTagBase64, 'base64');
        const saltBuf = Buffer.from(saltBase64, 'base64');

        const keyBuffer = await deriveKey(secret, saltBuf);

        const decipher = createDecipheriv('aes-256-gcm', keyBuffer, ivBuf);
        decipher.setAuthTag(authTagBuf);

        let decrypted = decipher.update(ciphertextBuf, undefined, 'utf8');
        decrypted += decipher.final('utf8'); // may throw if auth fails

        try {
          const parsed = JSON.parse(decrypted);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(parsed));
        } catch (e) {
          // Decrypted payload isn't JSON — return as text
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end(decrypted);
        }
      } catch (e) {
        console.error('Decryption failed:', e);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Decryption failed', details: e.message }));
      }
      return;
    }

    // Fallback
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  } catch (globalErr) {
    // Ensure CORS headers are present even on unexpected errors
    try { setCorsHeaders(res); } catch (e) { /* ignore */ }
    console.error('Unexpected error in request handler:', globalErr);
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal Server Error' }));
    } else {
      res.end();
    }
  }
});

server.listen(PORT, () => {
  console.log(`Test server running at http://localhost:${PORT}/ (PORT=${PORT})`);
});
