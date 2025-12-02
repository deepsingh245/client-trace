/**
 * CSP Violation Listener
 * Listens for Content Security Policy violations.
 */

/**
 * Starts listening for CSP violations.
 * @param {function} onViolation - Callback to handle violation details.
 */
export function listenForCSPViolations(onViolation) {
    document.addEventListener('securitypolicyviolation', (e) => {
        const report = {
            blockedURI: e.blockedURI,
            violatedDirective: e.violatedDirective,
            originalPolicy: e.originalPolicy,
            sourceFile: e.sourceFile,
            lineNumber: e.lineNumber,
            columnNumber: e.columnNumber,
            statusCode: e.statusCode,
            sample: e.sample,
        };

        if (onViolation) {
            onViolation(report);
        }
    });
}
