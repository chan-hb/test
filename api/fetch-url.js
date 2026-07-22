export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "url is required" });

  // Basic URL validation
  let parsed;
  try {
    parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return res.status(400).json({ error: "Only http/https URLs are supported" });
    }
  } catch(e) {
    return res.status(400).json({ error: `Invalid URL: ${e.message}` });
  }

  try {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; HB-SecurityAudit/1.0)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
      redirect: "follow",
      // 10 second timeout via AbortController
      signal: AbortSignal.timeout(10000)
    });

    const contentType = response.headers.get("content-type") || "";
    const body = await response.text();

    // Collect all security-relevant response headers
    const securityHeaders = {};
    const HEADERS_TO_CHECK = [
      "content-security-policy",
      "strict-transport-security",
      "x-frame-options",
      "x-content-type-options",
      "referrer-policy",
      "permissions-policy",
      "x-xss-protection",
      "cross-origin-embedder-policy",
      "cross-origin-opener-policy",
    ];
    HEADERS_TO_CHECK.forEach(h => {
      const val = response.headers.get(h);
      securityHeaders[h] = val || null; // null = missing, string = present with value
    });

    return res.status(200).json({
      ok: true,
      status: response.status,
      finalUrl: response.url,
      contentType,
      bodyLength: body.length,
      // Send first 60000 chars of body for audit
      body: body.slice(0, 60000),
      truncated: body.length > 60000,
      securityHeaders
    });

  } catch(err) {
    const isTimeout = err.name === "TimeoutError" || err.message.includes("timeout");
    return res.status(502).json({
      error: isTimeout
        ? "Request timed out after 10 seconds. The site may be slow or blocking automated requests."
        : `Fetch failed: ${err.message}`
    });
  }
}
