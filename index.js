const dns = require("node:dns");
const crypto = require("crypto");
function uniqueUserId(headers, socket, force = false) {
  try {
    let forcedIp;
    if (force) {
      try {
        dns.lookup(headers.origin, (address, family) => {
          forcedIp = address;
        });
      } catch (error) {
        throw new Error(error);
      }
    }

    // Extract header information and provide fallback values
    const ip =
      headers["remoteAddress"] ??
      headers["x-forwarded-for"] ??
      socket.remoteAddress ??
      forcedIp ??
      "unknown";
    const platform = headers["sec-ch-ua-platform"] || "unknown";
    const device = headers["user-agent"] || "unknown";
    const deviceType = headers["X-Device-Type"] || "unknown";
    const browser = headers["sec-ch-ua"] || "unknown";

    // Generate a unique ID
    const uniqueId = `${ip}-${platform}-${device}-${deviceType}-${browser}`;
    const hashedId = crypto.createHash("sha256").update(uniqueId).digest("hex");

    return hashedId;
  } catch (error) {
    console.error("Error in uniqueUserId:", error?.message || error);
    return null; // Return null on failure
  }
}

module.exports = { uniqueUserId };
