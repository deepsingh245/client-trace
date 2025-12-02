/**
 * Script Injection / Extension Detection
 * Detects unauthorized script injections and suspicious globals.
 */

let observer = null;
const knownScripts = new Set();

/**
 * Starts monitoring for script injections and checks for suspicious globals.
 * @param {string[]} [allowedGlobals] - List of allowed global variables.
 * @param {function} [onDetection] - Callback fired when injection is suspected.
 * @returns {{ extensionSuspected: boolean, injectedScripts: string[], suspiciousGlobals: string[] }}
 */
export function detectInjections(allowedGlobals = [], onDetection) {
    const suspiciousGlobals = [];
    const injectedScripts = [];

    // 1. Check for suspicious globals
    const commonExtensionGlobals = [
        'chrome', 'browser', 'safari', 'firefox', '__REACT_DEVTOOLS_GLOBAL_HOOK__'
    ];

    // Combine defaults with user allowed list to filter
    // Actually we want to find things that ARE in commonExtensionGlobals but NOT allowed?
    // Or just report anything in commonExtensionGlobals?
    // Usually extensions inject 'chrome' etc.

    commonExtensionGlobals.forEach(g => {
        if (window[g] && !allowedGlobals.includes(g)) {
            suspiciousGlobals.push(g);
        }
    });

    // 2. Track existing scripts
    document.querySelectorAll('script').forEach(s => {
        if (s.src) knownScripts.add(s.src);
    });

    // 3. Start MutationObserver
    if (!observer) {
        observer = new MutationObserver((mutations) => {
            mutations.forEach(mutation => {
                mutation.addedNodes.forEach(node => {
                    if (node.tagName === 'SCRIPT') {
                        const src = node.src || 'inline';
                        if (!knownScripts.has(src)) {
                            injectedScripts.push(src);
                            if (onDetection) {
                                onDetection({
                                    type: 'script_injection',
                                    src: src
                                });
                            }
                        }
                    }
                });
            });
        });

        observer.observe(document.documentElement, {
            childList: true,
            subtree: true
        });
    }

    return {
        extensionSuspected: suspiciousGlobals.length > 0,
        injectedScripts, // Note: this will be empty on first call usually, populated by observer later
        suspiciousGlobals
    };
}

export function stopInjectionMonitoring() {
    if (observer) {
        observer.disconnect();
        observer = null;
    }
}
