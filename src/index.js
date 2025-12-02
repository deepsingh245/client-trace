import { verifyBundleIntegrity } from './integrity/bundleCheck.js';
import { generateSessionToken } from './integrity/sessionToken.js';
import { detectNetworkAPITampering } from './network/tamperDetect.js';
import { detectProxy } from './network/proxyDetect.js';
import { detectTimingAnomalies } from './network/timingDetect.js';
import { getDeviceFingerprint } from './fingerprint/device.js';
import { detectBot, startBehaviorMonitoring, stopBehaviorMonitoring } from './fingerprint/botDetect.js';
import { detectInjections, stopInjectionMonitoring } from './security/injectionDetect.js';
import { listenForCSPViolations } from './security/cspListener.js';
import { checkStorageIntegrity, monitorStorage } from './security/storageCheck.js';
import { getNonce } from './transport/nonce.js';

// Re-export individual modules for granular usage
export * from './integrity/bundleCheck.js';
export * from './integrity/sessionToken.js';
export * from './network/tamperDetect.js';
export * from './network/proxyDetect.js';
export * from './network/timingDetect.js';
export * from './fingerprint/device.js';
export * from './fingerprint/botDetect.js';
export * from './security/injectionDetect.js';
export * from './security/cspListener.js';
export * from './security/storageCheck.js';
export * from './transport/signing.js';
export * from './transport/encryption.js';
export * from './transport/nonce.js';

/**
 * Collects a full security report by running all available checks.
 * Note: Some checks are async, so this returns a Promise.
 * 
 * @param {object} config - Configuration for the report.
 * @param {string} [config.bundleUrl] - URL for bundle integrity check.
 * @param {string} [config.expectedBundleHash] - Expected hash for bundle integrity.
 * @param {string} [config.pingUrl] - URL for proxy/timing checks.
 * @param {string} [config.userUniqueId] - User ID for session token.
 * @param {string} [config.hashedIp] - Hashed IP for session token.
 * @param {string} [config.secret] - Shared secret for session token.
 * @returns {Promise<object>} - The aggregated security report.
 */
export async function collectSecurityReport(config = {}) {
    const report = {};

    // 1. Bundle Integrity
    if (config.bundleUrl && config.expectedBundleHash) {
        report.bundleIntegrity = await verifyBundleIntegrity(config.bundleUrl, config.expectedBundleHash);
    }

    // 2. Network Tampering
    report.networkTampering = detectNetworkAPITampering();

    // 3. Device Fingerprint
    report.deviceFingerprint = await getDeviceFingerprint();

    // 4. Session Integrity
    if (config.userUniqueId && config.hashedIp && config.secret) {
        report.sessionIntegrity = await generateSessionToken(config.userUniqueId, config.hashedIp, config.secret);
    }

    // 5. Proxy Detection
    if (config.pingUrl) {
        report.proxyDetection = await detectProxy(config.pingUrl);
    }

    // 6. Script Injection
    // Note: This returns current state; observer continues running if started separately
    report.scriptInjection = detectInjections();

    // 7. Bot Signals
    report.botSignals = detectBot();

    // 8. Timing Anomalies
    if (config.pingUrl) {
        report.timingAnomalies = await detectTimingAnomalies(config.pingUrl);
    }

    // 9. Nonce
    report.nonceInfo = getNonce();

    // 10. Storage Tampering
    report.storageTampering = await checkStorageIntegrity();

    return report;
}
