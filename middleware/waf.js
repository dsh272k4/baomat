// middleware/waf.js
import fs from "fs";
import path from "path";

const logDir = path.resolve("logs");
const wafLog = path.join(logDir, "waf.log");
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

export function simpleWAF(req, res, next) {
    try {
        const bodyText = JSON.stringify(req.body || {});
        const queryText = JSON.stringify(req.query || {});
        const payload = (bodyText + queryText).toUpperCase();

        const blacklist = [
            "DROP TABLE",
            "UNION SELECT",
            "--",
            "/*",
            "*/",
            "XP_CMDSHELL",
            "<SCRIPT>",
            "ALERT(",
            "OR 1=1",
            "SLEEP(",
            "BENCHMARK("
        ];

        const found = blacklist.find((p) => payload.includes(p));
        if (found) {
            const log = `[${new Date().toISOString()}] BLOCKED IP=${req.ip} PATTERN=${found} PATH=${req.path}\n`;
            fs.appendFileSync(wafLog, log);
            return res.status(403).json({ message: "Request blocked by WAF" });
        }
    } catch (err) {
        console.error("WAF error:", err);
    }
    next();
}