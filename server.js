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

// 🔧 TẠM THỜI TẮT CSP TRONG BACKEND - Để reCAPTCHA hoạt động
app.use(helmet({
    contentSecurityPolicy: false
}));

// Hoặc nếu muốn giữ CSP, sử dụng cấu hình rất mở:
/*
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'", "https:", "http:", "data:", "blob:"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https:", "http:"],
            styleSrc: ["'self'", "'unsafe-inline'", "https:", "http:"],
            imgSrc: ["'self'", "data:", "https:", "http:", "blob:"],
            fontSrc: ["'self'", "https:", "http:"],
            connectSrc: ["'self'", "https:", "http:", "wss:"],
            frameSrc: ["'self'", "https:", "http:"],
            objectSrc: ["'none'"]
        }
    },
    crossOriginEmbedderPolicy: false
}));
*/

app.use(cors({
    origin: [
        "https://dta2k4.shop",
        "https://baomat.onrender.com",
        "http://localhost:3000"
    ],
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true
}));

app.use(express.json({ limit: '1mb' }));
app.use(rateLimit({
    windowMs: 60 * 1000,
    max: 100,
    message: {
        message: "Quá nhiều request, vui lòng thử lại sau 1 phút",
        code: "RATE_LIMIT_EXCEEDED"
    }
}));

// XSS Middleware
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
    res.json({
        status: "ok",
        time: new Date().toISOString(),
        security: "XSS-Protected"
    });
});

// start server
app.listen(PORT, () => {
    console.log(`🚀 Backend running on port ${PORT}`);
    console.log(`🔒 XSS Protection Enabled - reCAPTCHA Ready`);
});