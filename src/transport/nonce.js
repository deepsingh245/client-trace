/**
 * Nonce-Based Replay Protection
 * Generates and rotates nonces to prevent replay attacks.
 */

const STORAGE_KEY = 'ct_nonce_data';

/**
 * Gets or generates a nonce, rotating it if expired (24 hours).
 * @returns {{ nonce: string, rotated: boolean }}
 */
export function getNonce() {
    const now = Date.now();
    const stored = localStorage.getItem(STORAGE_KEY);
    let data = stored ? JSON.parse(stored) : null;
    let rotated = false;

    if (!data || (now - data.timestamp > 24 * 60 * 60 * 1000)) {
        // Generate new nonce
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        const nonce = Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');

        data = {
            nonce,
            timestamp: now
        };
        localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
        rotated = true;
    }

    return {
        nonce: data.nonce,
        rotated
    };
}
