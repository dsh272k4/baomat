// secure-backend/server.js
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import fetch from "node-fetch";
import fs from "fs";
import path from "path";
import authRoutes from "./routes/auth.js";
import adminRoutes from "./routes/admin.js";
import logRoutes from "./routes/logs.js";
import verifyToken from "./middleware/verifyToken.js";
import checkPasswordExpiry from "./middleware/checkPasswordExpiry.js";

dotenv.config();
const app = express();

app.use(express.json());
app.use(helmet());

// CORS cho domain thật + Render frontend
app.use(
    cors({
        origin: [
            "https://dta2k4.shop",
            "https://www.dta2k4.shop",
            "https://secure-frontend.onrender.com",
            "http://localhost:3000"
        ],
        credentials: true,
    })
);

// Rate limit
const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
});
app.use(limiter);

// Log folder Render (/tmp only)
const wafLog = "/tmp/waf.log";
const adminLog = "/tmp/admin.log";

// SIMPLE WAF
app.use((req, res, next) => {
    const payload = JSON.stringify(req.body).toLowerCase();
    const blacklist = ["drop table", "union select", "--", "/*", "*/", "<script", "<?php"];

    if (blacklist.some((word) => payload.includes(word))) {
        fs.appendFileSync(
            wafLog,
            `[${new Date().toISOString()}] Blocked: ${req.ip} Payload=${payload}\n`
        );
        return res.status(400).json({ message: "Payload bị chặn bởi WAF" });
    }
    next();
});

// Middleware check password expiry
app.use("/api", verifyToken, checkPasswordExpiry);

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/admin", verifyToken, adminRoutes);
app.use("/api/admin", logRoutes);

// Run server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`Backend running on Render port ${PORT}`);
});
