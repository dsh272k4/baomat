import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import { fileURLToPath } from 'url';

// Fix __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

import { pool } from "./config/db.js";
import { simpleWAF } from "./middleware/waf.js";
import { checkPasswordExpiry } from "./middleware/passwordPolicy.js";
import { verifyToken } from "./middleware/auth.js";
import authRoutes from "./routes/authRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";
import logRoutes from "./routes/logRoutes.js";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3001;

// ensure logs dir - FIX FOR RENDER.COM
const logDir = process.env.NODE_ENV === 'production' ? '/tmp/logs' : path.resolve("logs");
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}

// middlewares với config cho production
app.use(cors({
    origin: [
        "https://dta2k4.shop",
        "https://www.dta2k4.shop", 
        "http://localhost:3000"
    ],
    credentials: true
}));

app.use(helmet({
    contentSecurityPolicy: false, // Tắt CSP để frontend hoạt động tốt
    crossOriginEmbedderPolicy: false
}));

app.use(express.json({ limit: '10mb' }));
app.use(rateLimit({ 
    windowMs: 60 * 1000, 
    max: 100,
    message: 'Quá nhiều request, vui lòng thử lại sau 1 phút.'
}));
app.use(simpleWAF);

// test DB
pool.query("SELECT 1")
    .then(() => console.log("✅ MySQL connected"))
    .catch((e) => console.error("MySQL connection error:", e));

// routes prefix /api
app.use("/api", authRoutes);
app.use("/api", adminRoutes);
app.use("/api", logRoutes);

// Thêm middleware kiểm tra hết hạn mật khẩu cho các route cần auth
app.use("/api", verifyToken, checkPasswordExpiry);

// health endpoint cho Render
app.get("/health", (req, res) => res.json({ 
    status: "ok", 
    time: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
}));

// root endpoint
app.get("/", (req, res) => {
    res.json({ 
        message: "Secure Backend API is running 🚀",
        version: "1.0.0",
        environment: process.env.NODE_ENV || 'development',
        docs: "/health"
    });
});

// ensure default admin exists (optional)
import bcrypt from "bcrypt";
async function ensureAdmin() {
    try {
        const [rows] = await pool.query("SELECT id FROM users WHERE role='admin' LIMIT 1");
        if (rows.length === 0) {
            // Sử dụng mật khẩu mạnh mặc định
            const strongPassword = process.env.DEFAULT_ADMIN_PASSWORD || "Admin@Secure123!";
            const hash = await bcrypt.hash(strongPassword, 12);
            const now = new Date();

            await pool.query(
                "INSERT INTO users (username, password_hash, role, is_locked, created_at, password_changed_at) VALUES (?, ?, 'admin', 0, NOW(), ?)",
                ["admin", hash, now]
            );
            console.log("✅ Default admin created (username: admin)");
            console.log("⚠️  Please change the default admin password immediately!");
        } else {
            console.log("✅ Admin user already exists");
        }
    } catch (err) {
        console.error("Ensure admin error:", err);
    }
}

// error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err.stack);
    res.status(500).json({ 
        message: 'Something went wrong!',
        error: process.env.NODE_ENV === 'production' ? {} : err.message
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ 
        message: 'Route not found',
        path: req.originalUrl
    });
});

// start server - FIX FOR RENDER.COM
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Backend running on port ${PORT}`);
    console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
    
    // Create admin in production
    if (process.env.NODE_ENV === 'production') {
        ensureAdmin();
    }
});