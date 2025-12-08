/**
 * Encrypted Telemetry Transport
 * Encrypts data using AES-GCM before sending.
 */

/**
 * Derives an AES-GCM key from a shared secret using PBKDF2.
 * @param {string} secret - The shared secret.
 * @param {Uint8Array} salt - The salt.
 * @returns {Promise<CryptoKey>}
 */
async function deriveKey(secret, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );

    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

/**
 * Encrypts a payload.
 * @param {object} payload - The data to encrypt.
 * @param {string} secret - The shared secret.
 * @returns {Promise<{ iv: string, ciphertext: string, salt: string }>}
 */
export async function encryptTelemetry(payload, secret) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(secret, salt);

    const encoder = new TextEncoder();
    const data = encoder.encode(JSON.stringify(payload));

    const ciphertextBuffer = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        key,
        data
    );

    // Convert to Base64 for transport
    const toBase64 = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));

    return {
        iv: toBase64(iv),
        ciphertext: toBase64(ciphertextBuffer),
        salt: toBase64(salt)
    };
}

/**
 * Decrypts a payload (Client-side helper, mostly for verification/testing).
 */
export async function decryptTelemetry(encryptedData, secret) {
    const fromBase64 = (str) => {
        const binaryString = atob(str);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes;
    };

    const salt = fromBase64(encryptedData.salt);
    const iv = fromBase64(encryptedData.iv);
    const ciphertext = fromBase64(encryptedData.ciphertext);

    const key = await deriveKey(secret, salt);

    const decryptedBuffer = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        key,
        ciphertext
    );

    const decoder = new TextDecoder();
    return JSON.parse(decoder.decode(decryptedBuffer));
}
