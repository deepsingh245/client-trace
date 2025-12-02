/**
 * Network API Tampering Detection
 * Detects if fetch, XMLHttpRequest, or other network APIs have been monkey-patched.
 */

/**
 * Checks if a function has been tampered with by inspecting its toString() output.
 * @param {Function} func - The function to check.
 * @returns {boolean} - True if tampered (does not contain "[native code]"), false otherwise.
 */
function isNative(func) {
    return func.toString().includes('[native code]');
}

/**
 * Detects if network APIs (fetch, XHR) have been tampered with.
 * @param {function} [onTamperDetected] - Optional callback fired if tampering is found.
 * @returns {{ tampered: boolean, tamperedFunctions: string[] }}
 */
export function detectNetworkAPITampering(onTamperDetected) {
    const tamperedFunctions = [];

    if (typeof window.fetch !== 'undefined' && !isNative(window.fetch)) {
        tamperedFunctions.push('fetch');
    }

    if (typeof window.XMLHttpRequest !== 'undefined') {
        if (!isNative(window.XMLHttpRequest.prototype.open)) {
            tamperedFunctions.push('XMLHttpRequest.prototype.open');
        }
        if (!isNative(window.XMLHttpRequest.prototype.send)) {
            tamperedFunctions.push('XMLHttpRequest.prototype.send');
        }
    }

    const tampered = tamperedFunctions.length > 0;

    if (tampered && onTamperDetected) {
        onTamperDetected({ tampered, tamperedFunctions });
    }

    return {
        tampered,
        tamperedFunctions
    };
}
