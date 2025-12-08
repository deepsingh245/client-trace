/**
 * Session Integrity Token Generator
 * Creates a signed token binding the session to the user, IP (hashed), and UA.
 */

/**
 * Generates a session integrity token.
 * @param {string} userUniqueId - Unique identifier for the user.
 * @param {string} hashedIp - SHA-256 hash of the user's IP address (provided by server/caller).
 * @param {string} secret - Shared secret for HMAC signing.
 * @param {number} [timestampBucketSize=300000] - Time bucket size in ms (default 5 min).
 * @returns {Promise<{ sessionToken: string, components: object }>}
 */
export async function generateSessionToken(userUniqueId, hashedIp, secret, timestampBucketSize = 300000) {
    const userAgent = navigator.userAgent;
    const timestamp = Date.now();
    const timeBucket = Math.floor(timestamp / timestampBucketSize);

    const components = {
        userUniqueId,
        hashedIp,
        userAgent,
        timeBucket
    };

    const dataToSign = JSON.stringify(components);
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    const messageData = encoder.encode(dataToSign);

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

    // Token format: version.base64(components).signature
    const componentsBase64 = btoa(dataToSign);
    const sessionToken = `v1.${componentsBase64}.${signatureHex}`;

    return {
        sessionToken,
        components
    };
}
