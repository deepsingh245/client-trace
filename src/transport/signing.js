/**
 * Request Payload Signing
 * Signs outgoing telemetry using HMAC-SHA256 to ensure authenticity and integrity.
 */

/**
 * Signs a payload object.
 * @param {object} payload - The data to sign.
 * @param {string} secret - The shared secret key.
 * @returns {Promise<{ payload: object, timestamp: number, signature: string }>}
 */
export async function signPayload(payload, secret) {
    const timestamp = Date.now();

    // Canonical JSON stringify (simple version: sort keys)
    // For robust canonicalization, a library might be needed, but this suffices for simple objects.
    const canonicalize = (obj) => {
        if (typeof obj !== 'object' || obj === null) return JSON.stringify(obj);
        if (Array.isArray(obj)) return JSON.stringify(obj.map(canonicalize));
        const sortedKeys = Object.keys(obj).sort();
        const result = {};
        sortedKeys.forEach(key => {
            result[key] = obj[key];
        });
        return JSON.stringify(result);
    };

    const dataString = canonicalize(payload) + timestamp;
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    const messageData = encoder.encode(dataString);

    const key = await crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', key, messageData);
    const signatureArray = Array.from(new Uint8Array(signature));
    const signatureHex = signatureArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return {
        payload,
        timestamp,
        signature: signatureHex
    };
}
