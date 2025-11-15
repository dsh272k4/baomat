import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";

import { pool } from "./config/db.js";
import { simpleWAF } from "./middleware/waf.js";
import { checkPasswordExpiry } from "./middleware/passwordPolicy.js";
// 🔒 THÊM DÒNG NÀY - XSS Protection
import { xssMiddleware, strictXSSMiddleware } from "./middleware/xssSanitizer.js";

import authRoutes from "./routes/authRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";
import logRoutes from "./routes/logRoutes.js";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3001;

// Render chỉ cho ghi file tại /tmp
const logDir = "/tmp/logs";
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

app.use(cors({
    origin: [
        "https://dta2k4.shop",
        "https://baomat.onrender.com"
    ],
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true
}));

app.use(helmet());
app.use(express.json());
app.use(rateLimit({ windowMs: 60 * 1000, max: 100 }));

// 🔒 THÊM 2 DÒNG NÀY - XSS Middleware
app.use(xssMiddleware);
app.use(strictXSSMiddleware);

app.use(simpleWAF);
app.use(checkPasswordExpiry);

// test DB
pool.query("SELECT 1")
    .then(() => console.log("✅ MySQL connected"))
    .catch((e) => console.error("MySQL connection error:", e));

// routes
app.use("/api", authRoutes);
app.use("/api", adminRoutes);
app.use("/api", logRoutes);

// health
app.get("/health", (req, res) => {
    res.json({ status: "ok", time: new Date().toISOString() });
});

// start server
app.listen(PORT, () => {
    console.log(`🚀 Backend running on port ${PORT}`);
    console.log(`🔒 XSS Protection Enabled`); // THÊM DÒNG NÀY
});
app.get("/health", (req, res) => {
    res.json({
        status: "ok",
        time: new Date().toISOString(),
        security: "XSS-Protected",
        email: emailService.isEnabled ? "enabled" : "disabled",
        emailRetries: emailService.retryCount
    });
});

// Thêm route để manual check email service
app.get("/health/email", async (req, res) => {
    try {
        const wasEnabled = emailService.isEnabled;
        const isConnected = await emailService.verifyConnection();

        res.json({
            email_service: emailService.isEnabled ? "enabled" : "disabled",
            connection: isConnected ? "connected" : "disconnected",
            retry_count: emailService.retryCount,
            previous_status: wasEnabled ? "enabled" : "disabled",
            message: isConnected ? "Email service is working" : "Email service has issues"
        });
    } catch (error) {
        res.status(500).json({
            email_service: "error",
            error: error.message
        });
    }
});

// Thêm route để manual enable/disable email service
app.post("/health/email/:action", (req, res) => {
    const { action } = req.params;

    if (action === 'enable') {
        emailService.setEnabled(true);
        res.json({ message: "Email service enabled" });
    } else if (action === 'disable') {
        emailService.setEnabled(false);
        res.json({ message: "Email service disabled" });
    } else {
        res.status(400).json({ message: "Invalid action. Use 'enable' or 'disable'" });
    }
});
