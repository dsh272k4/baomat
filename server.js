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
import { xssMiddleware, strictXSSMiddleware } from "./middleware/xssSanitizer.js"; // THÊM XSS MIDDLEWARE
import authRoutes from "./routes/authRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";
import logRoutes from "./routes/logRoutes.js";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3001;

// Render chỉ cho ghi file tại /tmp
const logDir = "/tmp/logs";
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

// Security Headers với CSP mạnh mẽ
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            // 💡 SỬA ĐỔI TẠI ĐÂY
            scriptSrc: [
                "'self'",
                "'unsafe-inline'",
                "'unsafe-eval'", // <-- THÊM ĐỂ SỬA LỖI EVAL() CỦA RECAPTCHA
                "https://www.google.com",
                "https://www.gstatic.com"
            ],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            imgSrc: ["'self'", "data:", "https:"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            connectSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'self'", "https://www.google.com"] // Dòng này đã đúng
        }
    },
    crossOriginEmbedderPolicy: false,
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

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

app.use(express.json({ limit: '1mb' })); // Giới hạn kích thước JSON
app.use(rateLimit({
    windowMs: 60 * 1000,
    max: 100,
    message: {
        message: "Quá nhiều request, vui lòng thử lại sau 1 phút",
        code: "RATE_LIMIT_EXCEEDED"
    }
}));

// THÊM CÁC MIDDLEWARE XSS VÀO ĐÂY
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
        security: "XSS-Protected",
        features: ["WAF", "XSS Protection", "Rate Limiting", "CSP"]
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        message: "Route không tồn tại",
        code: "ROUTE_NOT_FOUND"
    });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('Global error handler:', err);

    // Không leak thông tin error trong production
    const message = process.env.NODE_ENV === 'production'
        ? "Lỗi máy chủ nội bộ"
        : err.message;

    res.status(500).json({
        message,
        code: "INTERNAL_SERVER_ERROR"
    });
});

// start server
app.listen(PORT, () => {
    console.log(`🚀 Backend running on port ${PORT}`);
    console.log(`🔒 Security features: XSS Protection, WAF, Rate Limiting, CSP`);
});