/**
 * Bundle Integrity Verification
 * Detects if the client bundle has been modified or tampered with.
 */

/**
 * Verifies the integrity of the client bundle by fetching it and comparing the hash.
 * @param {string} bundleUrl - The URL of the bundle to check (e.g., '/client-trace.js').
 * @param {string} expectedHash - The expected SHA-256 hash of the bundle.
 * @param {function} [onIntegrityFail] - Optional callback to trigger if integrity fails.
 * @returns {Promise<{ integrityOk: boolean, actualHash: string }>}
 */
export async function verifyBundleIntegrity(bundleUrl, expectedHash, onIntegrityFail) {
    try {
        const response = await fetch(bundleUrl);
        if (!response.ok) {
            throw new Error(`Failed to fetch bundle: ${response.statusText}`);
        }
        const buffer = await response.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const actualHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        const integrityOk = actualHash === expectedHash;

        if (!integrityOk && onIntegrityFail) {
            onIntegrityFail({
                expected: expectedHash,
                actual: actualHash,
                url: bundleUrl
            });
        }

        return { integrityOk, actualHash };
    } catch (error) {
        console.error('Bundle integrity check error:', error);
        return { integrityOk: false, actualHash: null, error: error.message };
    }
}
