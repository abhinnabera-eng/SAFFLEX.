
const express = require("express");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 10000;
const API_KEY = process.env.GOOGLE_WEBRISK_API_KEY;

app.use(express.json({ limit: "10kb" }));

// Replace this with your actual GitHub Pages origin.
const allowedOrigins = [
  "https://YOUR-USERNAME.github.io"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Origin not allowed"));
  }
}));

app.get("/", (req, res) => {
  res.json({ message: "SAFFLEX API is running" });
});

app.post("/api/scan", async (req, res) => {
  try {
    const { url } = req.body || {};

    if (typeof url !== "string" || url.length > 2048) {
      return res.status(400).json({
        verdict: "unable_to_scan",
        message: "Please enter a valid URL."
      });
    }

    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return res.status(400).json({
        verdict: "unable_to_scan",
        message: "Invalid URL."
      });
    }

    if (!["http:", "https:"].includes(parsed.protocol) ||
        parsed.username || parsed.password) {
      return res.status(400).json({
        verdict: "unable_to_scan",
        message: "Only HTTP and HTTPS URLs are accepted."
      });
    }

    if (!API_KEY) {
      return res.status(503).json({
        verdict: "unable_to_scan",
        message: "Threat detection is not configured."
      });
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    let response;
    try {
      response = await fetch(
        "https://webrisk.googleapis.com/v1/uris:search" +
        "?uri=" + encodeURIComponent(url) +
        "&threatTypes=SOCIAL_ENGINEERING" +
        "&threatTypes=MALWARE" +
        "&threatTypes=UNWANTED_SOFTWARE" +
        "&key=" + encodeURIComponent(API_KEY),
        { signal: controller.signal }
      );
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      throw new Error("Threat provider request failed");
    }

    const data = await response.json();
    const threats = data.threat || [];
    const reasonCodes = [];

    for (const threat of threats) {
      if (threat.threatType === "SOCIAL_ENGINEERING") {
        reasonCodes.push("known_phishing");
      }
      if (threat.threatType === "MALWARE") {
        reasonCodes.push("known_malware");
      }
      if (threat.threatType === "UNWANTED_SOFTWARE") {
        reasonCodes.push("unwanted_software");
      }
    }

    if (reasonCodes.length > 0) {
      return res.json({
        verdict: "dangerous",
        riskScore: 100,
        reasonCodes: [...new Set(reasonCodes)],
        message: "A known threat was identified."
      });
    }

    return res.json({
      verdict: "no_known_threat",
      riskScore: null,
      reasonCodes: [],
      message: "No known threat was found in this check. This does not guarantee safety."
    });

  } catch (error) {
    console.error("Scan failed:", error.message);

    return res.status(503).json({
      verdict: "unable_to_scan",
      message: "The scan could not be completed. Please try again."
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`SAFFLEX API running on port ${PORT}`);
});
