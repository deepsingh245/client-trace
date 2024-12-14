const dns = require("node:dns");
const crypto = require("crypto");
async function uniqueUserId(req, { force = false }) {
  try {
    let forcedIp;
    if (force) {
      try {
        dns.lookup(req.headers.origin, (address, family) => {
          forcedIp = address;
        });
      } catch (error) {
        throw new Error(error);
      }
    }

    // Extract header information and provide fallback values
    const xForwardedFor = req.headers["x-forwarded-for"];
    const ip =
      req.headers["remoteAddress"] ??
      xForwardedFor ??
      forcedIp ??
      req.socket.remoteAddress ??
      forcedIp ??
      "unknown";
    const platform = req.headers["sec-ch-ua-platform"] || "unknown";
    const device = req.headers["user-agent"] || "unknown";
    const deviceType = req.headers["X-Device-Type"] || "unknown";
    const browser = req.headers["sec-ch-ua"] || "unknown";

    // Generate a unique ID
    const uniqueId = `${ip}-${platform}-${device}-${deviceType}-${browser}`;
    const hashedId = crypto.createHash("sha256").update(uniqueId).digest("hex");
    return {
      hashedId,
    };
  } catch (error) {
    console.error("Error in uniqueUserId:", error?.message || error);
    return null; // Return null on failure
  }
}

module.exports = { uniqueUserId };
