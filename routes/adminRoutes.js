import express from "express";
import bcrypt from "bcrypt";
import fs from "fs";
import path from "path";
import { pool } from "../config/db.js";
import { verifyToken, requireAdmin } from "../middleware/auth.js";
import {
    validatePasswordStrength,
    updatePasswordHistory
} from "../middleware/passwordPolicy.js";

const router = express.Router();
const logDir = path.resolve("logs");
const adminLogPath = path.join(logDir, "admin.log");
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

function logAdminAction(admin, action, target) {
    const now = new Date();
    const vnTime = new Date(now.getTime() + 7 * 60 * 60 * 1000); // cộng thêm 7 tiếng
    const formatted = vnTime.toISOString().replace("T", " ").substring(0, 19);
    const logMsg = `[${formatted}] ${admin} -> ${action} ${target}\n`;

    console.log("📜 Ghi log admin:", logMsg.trim());
    fs.appendFileSync(adminLogPath, logMsg);
}

// GET /admin/users
router.get("/admin/users", verifyToken, requireAdmin, async (req, res) => {
    try {
        const [rows] = await pool.query("SELECT id, username, role, is_locked, created_at, password_changed_at FROM users ORDER BY id DESC");
        res.json(rows);
    } catch (err) {
        console.error("Get users error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

// POST /admin/users
router.post("/admin/users", verifyToken, requireAdmin, async (req, res) => {
    try {
        const { username, password, role } = req.body;
        if (!username || !password) return res.status(400).json({ message: "username & password required" });

        // Kiểm tra mật khẩu mạnh
        const strengthCheck = validatePasswordStrength(password);
        if (!strengthCheck.isValid) {
            return res.status(400).json({
                message: "Password is not strong enough",
                errors: strengthCheck.errors
            });
        }

        const [exists] = await pool.query("SELECT id FROM users WHERE username=?", [username]);
        if (exists.length) return res.status(400).json({ message: "Username already exists" });

        const hash = await bcrypt.hash(password, 12);
        const now = new Date();

        await pool.query(
            "INSERT INTO users (username, password_hash, role, is_locked, created_at, password_changed_at) VALUES (?, ?, ?, 0, NOW(), ?)",
            [username, hash, role || "user", now]
        );

        logAdminAction(req.user.username, "Create", username);
        res.json({ message: "User created" });
    } catch (err) {
        console.error("Create user error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

// PUT /admin/users/:id
router.put("/admin/users/:id", verifyToken, requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        const { username, role } = req.body;
        if (!username) return res.status(400).json({ message: "username required" });

        const [exists] = await pool.query("SELECT id FROM users WHERE username = ? AND id != ?", [username, id]);
        if (exists.length) return res.status(400).json({ message: "Username already exists" });

        await pool.query("UPDATE users SET username=?, role=? WHERE id=?", [username, role, id]);
        logAdminAction(req.user.username, "Update", `ID ${id} (${username})`);
        res.json({ message: "User updated" });
    } catch (err) {
        console.error("Update user error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

// PUT /admin/users/:id/lock
router.put("/admin/users/:id/lock", verifyToken, requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        const { lock } = req.body;
        await pool.query("UPDATE users SET is_locked = ? WHERE id = ?", [lock ? 1 : 0, id]);
        logAdminAction(req.user.username, lock ? "Lock" : "Unlock", `ID ${id}`);
        res.json({ message: lock ? "User locked" : "User unlocked" });
    } catch (err) {
        console.error("Lock user error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

// PUT /admin/users/:id/reset-password
router.put("/admin/users/:id/reset-password", verifyToken, requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        const { newPassword } = req.body;

        if (!newPassword) {
            return res.status(400).json({ message: "Vui lòng cung cấp mật khẩu mới" });
        }

        // Kiểm tra độ mạnh mật khẩu
        const strengthCheck = validatePasswordStrength(newPassword);
        if (!strengthCheck.isValid) {
            return res.status(400).json({
                message: "Mật khẩu mới không đủ mạnh",
                errors: strengthCheck.errors
            });
        }

        const [rows] = await pool.query("SELECT username FROM users WHERE id=?", [id]);
        if (!rows.length) return res.status(404).json({ message: "User not found" });

        const hash = await bcrypt.hash(newPassword, 12);
        const now = new Date();

        await pool.query(
            "UPDATE users SET password_hash=?, password_changed_at=?, failed_login_attempts=0, lockout_until=NULL WHERE id=?",
            [hash, now, id]
        );

        // Cập nhật lịch sử mật khẩu
        await updatePasswordHistory(id, hash, pool);

        logAdminAction(req.user.username, "ResetPassword", `${rows[0].username} (ID ${id})`);
        res.json({ message: "Password reset successfully" });

    } catch (err) {
        console.error("Reset password error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

// DELETE /admin/users/:id
router.delete("/admin/users/:id", verifyToken, requireAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        const [rows] = await pool.query("SELECT username FROM users WHERE id=?", [id]);
        if (!rows.length) return res.status(404).json({ message: "User not found" });

        await pool.query("DELETE FROM users WHERE id=?", [id]);
        logAdminAction(req.user.username, "Delete", `${rows[0].username} (ID ${id})`);
        res.json({ message: "User deleted" });
    } catch (err) {
        console.error("Delete user error:", err);
        res.status(500).json({ message: "Server error" });
    }
});
export default router;