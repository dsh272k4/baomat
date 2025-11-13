// secure-backend/routes/authRoutes.js
import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { pool } from "../config/db.js";
import dotenv from "dotenv";
import { verifyRecaptcha } from "../middleware/recaptcha.js";
import {
    validatePasswordStrength,
    isPasswordInHistory,
    updatePasswordHistory,
    PASSWORD_POLICY
} from "../middleware/passwordPolicy.js";
import { verifyToken } from "../middleware/auth.js";
import { emailService } from "../services/emailService.js";

dotenv.config();
const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || "2h";

// REGISTER
router.post("/auth/register", verifyRecaptcha, async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ message: "Vui lòng nhập đủ thông tin" });
        if (!/^[A-Za-z0-9_]{3,30}$/.test(username)) return res.status(400).json({ message: "Tên không hợp lệ" });

        // Kiểm tra mật khẩu mạnh cho đăng ký
        const strengthCheck = validatePasswordStrength(password);
        if (!strengthCheck.isValid) {
            return res.status(400).json({
                message: "Mật khẩu không đủ mạnh",
                errors: strengthCheck.errors
            });
        }

        const [exists] = await pool.query("SELECT id FROM users WHERE username=?", [username]);
        if (exists.length) return res.status(400).json({ message: "Tên người dùng đã tồn tại" });

        const hash = await bcrypt.hash(password, 12);
        const now = new Date();

        await pool.query(
            "INSERT INTO users (username, password_hash, role, failed_login_attempts, is_locked, created_at, password_changed_at, receive_login_alerts) VALUES (?, ?, 'user', 0, 0, NOW(), ?, 1)",
            [username, hash, now]
        );

        res.status(201).json({ message: "Đăng ký thành công! Hãy đăng nhập." });
    } catch (err) {
        console.error("Register error:", err);
        res.status(500).json({ message: "Lỗi máy chủ" });
    }
});

// LOGIN - Cập nhật để gửi email thông báo
router.post("/auth/login", verifyRecaptcha, async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ message: "Vui lòng nhập tên và mật khẩu" });

        const [rows] = await pool.query(
            "SELECT id, username, password_hash, role, failed_login_attempts, is_locked, lockout_until, password_changed_at, email, receive_login_alerts FROM users WHERE username=?",
            [username]
        );
        if (!rows.length) return res.status(401).json({ message: "Tài khoản hoặc mật khẩu sai" });

        const user = rows[0];
        const now = new Date();

        // 1️⃣ Kiểm tra khóa vĩnh viễn
        if (user.is_locked) return res.status(403).json({ message: "Tài khoản bị khóa bởi admin" });

        // 2️⃣ Kiểm tra khóa tạm thời
        if (user.lockout_until && now < user.lockout_until) {
            const remaining = Math.ceil((user.lockout_until - now) / 1000);
            return res.status(403).json({ message: `Tài khoản tạm khóa, thử lại sau ${remaining}s` });
        }

        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) {
            // tăng số lần đăng nhập sai
            let attempts = user.failed_login_attempts + 1;
            let lockout = null;

            const lockSteps = [30, 60, 300, 900, 3600]; // 30s,1p,5p,15p,1h
            if (attempts >= 5) {
                const index = Math.min(attempts - 5, lockSteps.length - 1);
                lockout = new Date(now.getTime() + lockSteps[index] * 1000);
                attempts = 5; // giữ max 5 lần
            }

            await pool.query(
                "UPDATE users SET failed_login_attempts=?, lockout_until=? WHERE id=?",
                [attempts, lockout, user.id]
            );

            if (lockout) {
                const secs = Math.ceil((lockout - now) / 1000);
                return res.status(403).json({ message: `Tài khoản tạm khóa ${secs} giây` });
            }

            return res.status(401).json({ message: "Tài khoản hoặc mật khẩu sai" });
        }

        // đăng nhập thành công → reset fail count + lockout
        await pool.query(
            "UPDATE users SET failed_login_attempts=0, lockout_until=NULL WHERE id=?",
            [user.id]
        );

        const token = jwt.sign(
            {
                id: user.id,
                username: user.username,
                role: user.role,
                password_changed_at: user.password_changed_at
            },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES }
        );

        // 🔐 GỬI EMAIL THÔNG BÁO ĐĂNG NHẬP NẾU USER CÓ EMAIL VÀ CHO PHÉP
        try {
            if (user.email && user.receive_login_alerts === 1) {
                const loginData = {
                    ip: req.ip || req.connection.remoteAddress || req.socket.remoteAddress || 'Không xác định',
                    browser: req.headers['user-agent'] || 'Không xác định',
                    loginTime: now.toLocaleString('vi-VN', {
                        timeZone: 'Asia/Ho_Chi_Minh',
                        year: 'numeric',
                        month: '2-digit',
                        day: '2-digit',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit'
                    })
                };

                console.log(`📧 Preparing to send login alert to: ${user.email}`);

                // Gửi email bất đồng bộ, không await để không làm chậm response
                emailService.sendLoginAlert(user.email, user.username, loginData)
                    .then(result => {
                        if (result.success) {
                            // Cập nhật thời gian gửi thông báo cuối
                            pool.query(
                                "UPDATE users SET last_login_notification = ? WHERE id = ?",
                                [now, user.id]
                            ).catch(dbError => {
                                console.error('Error updating notification time:', dbError);
                            });
                            console.log(`✅ Login notification sent to ${user.email}`);
                        }
                    })
                    .catch(emailError => {
                        console.error('Email sending failed:', emailError);
                    });
            } else {
                console.log(`📧 Email alert skipped for user ${user.username}:`, {
                    hasEmail: !!user.email,
                    wantsAlerts: user.receive_login_alerts === 1
                });
            }
        } catch (emailError) {
            console.error('Error in email notification process:', emailError);
            // Không throw error để không ảnh hưởng đến trải nghiệm đăng nhập
        }

        res.json({ token });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ message: "Lỗi máy chủ" });
    }
});

// GET /api/auth/profile - Cập nhật để lấy thêm thông tin email settings
router.get("/auth/profile", verifyToken, async (req, res) => {
    try {
        const [rows] = await pool.query(
            "SELECT id, username, full_name, email, phone, password_changed_at, receive_login_alerts FROM users WHERE id=?",
            [req.user.id]
        );
        if (!rows.length) return res.status(404).json({ message: "Không tìm thấy người dùng" });
        res.json(rows[0]);
    } catch (err) {
        console.error("Get profile error:", err);
        res.status(500).json({ message: "Lỗi máy chủ" });
    }
});

// Thêm route mới cho email settings
router.put("/auth/email-settings", verifyToken, async (req, res) => {
    try {
        const { receive_login_alerts } = req.body;

        await pool.query(
            "UPDATE users SET receive_login_alerts = ? WHERE id = ?",
            [receive_login_alerts ? 1 : 0, req.user.id]
        );

        res.json({ message: "Cập nhật cài đặt email thành công" });
    } catch (err) {
        console.error("Update email settings error:", err);
        res.status(500).json({ message: "Lỗi cập nhật cài đặt" });
    }
});

// PUT /api/auth/profile - Cập nhật thông tin profile
router.put("/auth/profile", verifyToken, async (req, res) => {
    try {
        const { full_name, email, phone } = req.body;

        // Kiểm tra email (nếu thay đổi) có bị trùng không
        if (email) {
            const [exists] = await pool.query(
                "SELECT id FROM users WHERE email=? AND id != ?",
                [email, req.user.id]
            );
            if (exists.length) {
                return res.status(400).json({ message: "Email này đã được sử dụng bởi tài khoản khác" });
            }
        }

        await pool.query(
            "UPDATE users SET full_name = ?, email = ?, phone = ? WHERE id = ?",
            [full_name, email, phone, req.user.id]
        );

        res.json({ message: "Cập nhật thông tin thành công" });
    } catch (err) {
        console.error("Update profile error:", err);
        res.status(500).json({ message: "Lỗi máy chủ" });
    }
});

// PUT /api/auth/change-password - Đổi mật khẩu với chính sách mới
router.put("/auth/change-password", verifyToken, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;

        if (!oldPassword || !newPassword) {
            return res.status(400).json({ message: "Vui lòng nhập mật khẩu cũ và mới" });
        }

        // 1. Kiểm tra độ mạnh mật khẩu mới
        const strengthCheck = validatePasswordStrength(newPassword);
        if (!strengthCheck.isValid) {
            return res.status(400).json({
                message: "Mật khẩu mới không đủ mạnh",
                errors: strengthCheck.errors
            });
        }

        // 2. Lấy thông tin user hiện tại
        const [rows] = await pool.query(
            "SELECT id, username, password_hash, password_changed_at, password_history FROM users WHERE id = ?",
            [req.user.id]
        );

        if (!rows.length) {
            return res.status(404).json({ message: "Không tìm thấy người dùng" });
        }

        const user = rows[0];

        // 3. Kiểm tra mật khẩu cũ
        const isOldPasswordMatch = await bcrypt.compare(oldPassword, user.password_hash);
        if (!isOldPasswordMatch) {
            return res.status(400).json({ message: "Mật khẩu cũ không chính xác" });
        }

        // 4. Kiểm tra mật khẩu mới không trùng với lịch sử (bắt lỗi)
        let isInHistory = false;
        try {
            isInHistory = await isPasswordInHistory(req.user.id, newPassword, pool);
        } catch (historyError) {
            console.error("Password history check failed, continuing:", historyError);
            // Tiếp tục mà không block user nếu có lỗi kiểm tra lịch sử
        }

        if (isInHistory) {
            return res.status(400).json({
                message: "Mật khẩu mới không được trùng với mật khẩu cũ. Vui lòng chọn mật khẩu khác."
            });
        }

        // 5. Hash và cập nhật mật khẩu mới
        const newHash = await bcrypt.hash(newPassword, 12);
        const now = new Date();

        await pool.query(
            "UPDATE users SET password_hash = ?, password_changed_at = ?, failed_login_attempts = 0, lockout_until = NULL WHERE id = ?",
            [newHash, now, req.user.id]
        );

        // 6. Cập nhật lịch sử mật khẩu (bắt lỗi)
        try {
            await updatePasswordHistory(req.user.id, newHash, pool);
        } catch (updateError) {
            console.error("Password history update failed, but password changed:", updateError);
            // Vẫn trả về success nhưng log lỗi
        }

        res.json({
            message: "Đổi mật khẩu thành công",
            nextExpiry: new Date(now.getTime() + (PASSWORD_POLICY.maxAgeDays * 24 * 60 * 60 * 1000)).toISOString()
        });

    } catch (err) {
        console.error("Change password error:", err);
        res.status(500).json({ message: "Lỗi máy chủ" });
    }
});

// GET /api/auth/password-policy - Lấy thông tin chính sách mật khẩu
router.get("/auth/password-policy", verifyToken, (req, res) => {
    res.json({
        policy: {
            minLength: PASSWORD_POLICY.minLength,
            requireUppercase: PASSWORD_POLICY.requireUppercase,
            requireLowercase: PASSWORD_POLICY.requireLowercase,
            requireNumbers: PASSWORD_POLICY.requireNumbers,
            requireSpecialChars: PASSWORD_POLICY.requireSpecialChars,
            maxAgeDays: PASSWORD_POLICY.maxAgeDays
        },
        description: "Mật khẩu phải có ít nhất 12 ký tự, bao gồm chữ hoa, chữ thường, số và ký tự đặc biệt. Mật khẩu cần được thay đổi mỗi 90 ngày."
    });
});

export default router;