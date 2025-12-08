/**
 * Lightweight Device Fingerprinting
 * Collects non-unique, privacy-safe signals to create a device identifier.
 */

/**
 * Generates a device fingerprint hash and returns collected components.
 * @returns {Promise<{ fingerprintHash: string, components: object }>}
 */
export async function getDeviceFingerprint() {
    const components = {
        userAgent: navigator.userAgent,
        language: navigator.language,
        languages: navigator.languages,
        platform: navigator.platform,
        hardwareConcurrency: navigator.hardwareConcurrency,
        deviceMemory: navigator.deviceMemory, // Optional, may be undefined
        screenResolution: `${window.screen.width}x${window.screen.height}`,
        colorDepth: window.screen.colorDepth,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        touchSupport: 'ontouchstart' in window || navigator.maxTouchPoints > 0,
    };

    // Filter out undefined values to ensure consistent hashing
    const cleanComponents = Object.keys(components).reduce((acc, key) => {
        if (components[key] !== undefined) {
            acc[key] = components[key];
        }
        return acc;
    }, {});

    const dataString = JSON.stringify(cleanComponents);
    const encoder = new TextEncoder();
    const data = encoder.encode(dataString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const fingerprintHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return {
        fingerprintHash,
        components: cleanComponents
    };
}
