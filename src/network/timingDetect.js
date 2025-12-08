/**
 * Timing Anomaly Detection
 * Measures network timing to detect potential MITM slowdowns.
 */

/**
 * Measures network timing metrics for a given URL.
 * @param {string} url - The URL to measure.
 * @param {object} [thresholds] - Baseline thresholds for anomaly detection.
 * @param {number} [thresholds.dns] - Max DNS lookup time in ms.
 * @param {number} [thresholds.ttfb] - Max Time To First Byte in ms.
 * @returns {Promise<{ anomaly: boolean, metrics: object }>}
 */
export async function detectTimingAnomalies(url, thresholds = { dns: 100, ttfb: 200 }) {
    const start = performance.now();
    try {
        await fetch(url, { cache: 'no-store', method: 'HEAD' });
        const totalDuration = performance.now() - start;

        // Get detailed entries if available
        const entries = performance.getEntriesByName(url);
        let metrics = { totalDuration };
        let anomaly = false;

        if (entries.length > 0) {
            const entry = entries[entries.length - 1]; // Get the most recent one
            const dns = entry.domainLookupEnd - entry.domainLookupStart;
            const ttfb = entry.responseStart - entry.requestStart;

            metrics = {
                ...metrics,
                dns,
                ttfb,
                tcp: entry.connectEnd - entry.connectStart
            };

            if (dns > thresholds.dns || ttfb > thresholds.ttfb) {
                anomaly = true;
            }
        } else {
            // Fallback if Resource Timing API is not available or cleared
            // Simple total duration check (rough estimate)
            if (totalDuration > (thresholds.ttfb + thresholds.dns + 50)) {
                anomaly = true;
            }
        }

        return {
            anomaly,
            metrics
        };
    } catch (error) {
        return { anomaly: false, error: error.message };
    }
}
