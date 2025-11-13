// secure-backend/server.js
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
});
