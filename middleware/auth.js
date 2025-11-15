import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

// SỬA LỖI CRITICAL: Xóa hardcoded secret
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    throw new Error("JWT_SECRET missing in environment variables");
}

export function verifyToken(req, res, next) {
    const auth = req.headers.authorization;

    if (!auth || !auth.startsWith("Bearer ")) {
        return res.status(401).json({
            message: "Token không hợp lệ",
            code: "MISSING_TOKEN"
        });
    }

    const token = auth.slice(7);

    // Kiểm tra độ dài token cơ bản
    if (token.length < 10) {
        return res.status(401).json({
            message: "Token không hợp lệ",
            code: "INVALID_TOKEN_FORMAT"
        });
    }

    try {
        const payload = jwt.verify(token, JWT_SECRET);

        // Validate payload cơ bản
        if (!payload.id || !payload.username) {
            return res.status(401).json({
                message: "Token payload không hợp lệ",
                code: "INVALID_TOKEN_PAYLOAD"
            });
        }

        req.user = payload;
        next();
    } catch (err) {
        console.error("JWT verification error:", err.message);

        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({
                message: "Token đã hết hạn",
                code: "TOKEN_EXPIRED"
            });
        }

        return res.status(401).json({
            message: "Token không hợp lệ",
            code: "INVALID_TOKEN"
        });
    }
}

export function requireAdmin(req, res, next) {
    if (!req.user) {
        return res.status(401).json({
            message: "Thiếu thông tin người dùng",
            code: "MISSING_USER_CONTEXT"
        });
    }

    if (req.user.role !== "admin") {
        return res.status(403).json({
            message: "Yêu cầu quyền admin",
            code: "ADMIN_REQUIRED"
        });
    }
    next();
}