// secure-backend/middleware/passwordPolicy.js
import bcrypt from "bcrypt";

// Chính sách mật khẩu
export const PASSWORD_POLICY = {
    minLength: 12,
    maxLength: 128,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    maxAgeDays: 90, // 90 ngày phải đổi mật khẩu
    passwordHistory: 5 // Lưu lịch sử 5 mật khẩu gần nhất
};

// Kiểm tra độ mạnh mật khẩu
export function validatePasswordStrength(password) {
    const errors = [];

    if (password.length < PASSWORD_POLICY.minLength) {
        errors.push(`Mật khẩu phải có ít nhất ${PASSWORD_POLICY.minLength} ký tự`);
    }

    if (password.length > PASSWORD_POLICY.maxLength) {
        errors.push(`Mật khẩu không được vượt quá ${PASSWORD_POLICY.maxLength} ký tự`);
    }

    if (PASSWORD_POLICY.requireUppercase && !/[A-Z]/.test(password)) {
        errors.push("Mật khẩu phải chứa ít nhất một chữ cái in hoa");
    }

    if (PASSWORD_POLICY.requireLowercase && !/[a-z]/.test(password)) {
        errors.push("Mật khẩu phải chứa ít nhất một chữ cái thường");
    }

    if (PASSWORD_POLICY.requireNumbers && !/\d/.test(password)) {
        errors.push("Mật khẩu phải chứa ít nhất một số");
    }

    if (PASSWORD_POLICY.requireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
        errors.push("Mật khẩu phải chứa ít nhất một ký tự đặc biệt");
    }

    // Kiểm tra mật khẩu phổ biến
    const commonPasswords = ["Password123!", "Admin123!", "Welcome123!", "Changeme123!", "Aa@123456789"];
    if (commonPasswords.includes(password)) {
        errors.push("Mật khẩu quá phổ biến, vui lòng chọn mật khẩu khác");
    }

    return {
        isValid: errors.length === 0,
        errors
    };
}

// Hàm parse JSON an toàn
function safeJsonParse(str) {
    try {
        return JSON.parse(str);
    } catch (error) {
        console.log("JSON parse failed, returning empty array");
        return [];
    }
}

// Kiểm tra mật khẩu không được trùng với lịch sử
export async function isPasswordInHistory(userId, newPassword, pool) {
    try {
        const [rows] = await pool.query(
            "SELECT password_history FROM users WHERE id = ?",
            [userId]
        );

        if (!rows.length || !rows[0].password_history) {
            return false;
        }

        let passwordHistory;
        const historyData = rows[0].password_history;

        // Xử lý cả trường hợp là string JSON và string thường
        if (typeof historyData === 'string') {
            if (historyData.startsWith('[')) {
                // Nếu là JSON array
                passwordHistory = safeJsonParse(historyData);
            } else {
                // Nếu là single hash string (trường hợp lỗi)
                passwordHistory = [historyData];
            }
        } else if (Array.isArray(historyData)) {
            // Nếu đã là array (trường hợp JSON column)
            passwordHistory = historyData;
        } else {
            passwordHistory = [];
        }

        console.log("Password history check:", {
            userId,
            historyLength: passwordHistory.length,
            historyType: typeof historyData
        });

        for (const oldHash of passwordHistory) {
            if (typeof oldHash === 'string') {
                const isMatch = await bcrypt.compare(newPassword, oldHash);
                if (isMatch) {
                    console.log("Password found in history");
                    return true;
                }
            }
        }

        return false;
    } catch (error) {
        console.error("Error checking password history:", error);
        return false; // Trả về false nếu có lỗi để không block user
    }
}

// Cập nhật lịch sử mật khẩu
export async function updatePasswordHistory(userId, newPasswordHash, pool) {
    try {
        const [rows] = await pool.query(
            "SELECT password_history FROM users WHERE id = ?",
            [userId]
        );

        let passwordHistory = [];

        if (rows.length && rows[0].password_history) {
            const historyData = rows[0].password_history;

            if (typeof historyData === 'string') {
                if (historyData.startsWith('[')) {
                    // Nếu là JSON array
                    passwordHistory = safeJsonParse(historyData);
                } else {
                    // Nếu là single hash string (trường hợp lỗi)
                    passwordHistory = [historyData];
                }
            } else if (Array.isArray(historyData)) {
                // Nếu đã là array
                passwordHistory = historyData;
            }
        }

        // Thêm mật khẩu mới vào đầu mảng
        passwordHistory.unshift(newPasswordHash);

        // Giữ chỉ số lượng mật khẩu gần nhất
        passwordHistory = passwordHistory.slice(0, PASSWORD_POLICY.passwordHistory);

        console.log("Updating password history:", {
            userId,
            newLength: passwordHistory.length,
            newHash: newPasswordHash.substring(0, 20) + "..."
        });

        await pool.query(
            "UPDATE users SET password_history = ? WHERE id = ?",
            [JSON.stringify(passwordHistory), userId]
        );

        console.log("Password history updated successfully");

    } catch (error) {
        console.error("Error updating password history:", error);
        // Không throw error để không block việc đổi mật khẩu
    }
}

// Kiểm tra mật khẩu đã hết hạn chưa
export function isPasswordExpired(passwordChangedAt) {
    if (!passwordChangedAt) return false;

    const changedDate = new Date(passwordChangedAt);
    const expiryDate = new Date(changedDate.getTime() + (PASSWORD_POLICY.maxAgeDays * 24 * 60 * 60 * 1000));
    return new Date() > expiryDate;
}

// Middleware kiểm tra mật khẩu đã hết hạn chưa
export function checkPasswordExpiry(req, res, next) {
    if (!req.user) return next();

    // Không kiểm tra cho route đổi mật khẩu
    if (req.path.includes('change-password') || req.path.includes('logout')) {
        return next();
    }

    // Lấy thông tin chi tiết user để kiểm tra password_changed_at
    pool.query(
        "SELECT password_changed_at FROM users WHERE id = ?",
        [req.user.id]
    ).then(([rows]) => {
        if (rows.length && isPasswordExpired(rows[0].password_changed_at)) {
            return res.status(403).json({
                message: "Mật khẩu của bạn đã hết hạn. Vui lòng đổi mật khẩu để tiếp tục sử dụng hệ thống.",
                code: "PASSWORD_EXPIRED",
                redirectTo: "/profile"
            });
        }
        next();
    }).catch(err => {
        console.error("Error checking password expiry:", err);
        next();
    });
}
