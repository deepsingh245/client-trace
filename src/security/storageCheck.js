/**
 * Local Tampering Detection
 * Monitors localStorage and cookies for unauthorized changes.
 */

/**
 * Computes a simple checksum of a string.
 */
async function computeChecksum(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

const storageChecksums = new Map();

/**
 * Initializes monitoring for specific localStorage keys.
 * @param {string[]} keys - Keys to monitor.
 */
export async function monitorStorage(keys) {
    for (const key of keys) {
        const value = localStorage.getItem(key) || '';
        const hash = await computeChecksum(value);
        storageChecksums.set(key, hash);
    }
}

/**
 * Checks for tampering in monitored storage keys.
 * @returns {Promise<{ storageTampered: boolean, tamperedKeys: string[] }>}
 */
export async function checkStorageIntegrity() {
    const tamperedKeys = [];

    for (const [key, expectedHash] of storageChecksums) {
        const currentValue = localStorage.getItem(key) || '';
        const currentHash = await computeChecksum(currentValue);

        if (currentHash !== expectedHash) {
            tamperedKeys.push(key);
        }
    }

    return {
        storageTampered: tamperedKeys.length > 0,
        tamperedKeys
    };
}

/**
 * Helper to check if cookies have changed (requires initial snapshot).
 * Note: HttpOnly cookies cannot be checked.
 */
export function getCookieSnapshot() {
    return document.cookie;
}

export function checkCookieChanges(initialSnapshot) {
    return document.cookie !== initialSnapshot;
}
