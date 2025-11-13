// routes/logRoutes.js
import express from "express";
import fs from "fs";
import path from "path";
import { verifyToken, requireAdmin } from "../middleware/auth.js";

const router = express.Router();

router.get("/admin/logs", verifyToken, requireAdmin, (req, res) => {
    try {
        const logDir = path.resolve("logs");
        const wafLogPath = path.join(logDir, "waf.log");
        const adminLogPath = path.join(logDir, "admin.log");

        const waf = fs.existsSync(wafLogPath) ? fs.readFileSync(wafLogPath, "utf-8") : "";
        const admin = fs.existsSync(adminLogPath) ? fs.readFileSync(adminLogPath, "utf-8") : "";
        res.json({ wafLog: waf, adminLog: admin });
    } catch (err) {
        console.error("Read logs error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

export default router;