/**
 * Proxy / MITM Detection
 * Detects potential proxies or MITM attacks by inspecting response headers.
 */

/**
 * Performs a test fetch to check for proxy signatures in headers.
 * @param {string} pingUrl - The URL to fetch (should be a simple endpoint like /trace-ping).
 * @returns {Promise<{ proxyLikely: boolean, detectedHeaders: object }>}
 */
export async function detectProxy(pingUrl) {
    try {
        const response = await fetch(pingUrl, { method: 'HEAD' });
        const headers = response.headers;

        const detectedHeaders = {};
        for (const [key, value] of headers.entries()) {
            detectedHeaders[key] = value;
        }
        const proxyHeaders = [
            'via',
            'x-forwarded-for',
            'x-cache',
            'x-varnish',
            'x-bluecoat-via',
            'cf-ray', // Cloudflare (common, but technically a proxy)
            'fastly-client-ip'
        ];

        let proxyLikely = false;

        proxyHeaders.forEach(header => {
            if (headers.has(header)) {
                detectedHeaders[header] = headers.get(header);
                proxyLikely = true;
            }
        });

        return {
            proxyLikely,
            detectedHeaders
        };
    } catch (error) {
        console.error('Proxy detection failed:', error);
        return { proxyLikely: false, error: error.message };
    }
}
