import dotenv from "dotenv";
dotenv.config();

// SỬA LỖI CRITICAL: Xóa hardcoded secret
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;
if (!RECAPTCHA_SECRET_KEY) {
    throw new Error("RECAPTCHA_SECRET_KEY missing in environment variables");
}

export const verifyRecaptcha = async (req, res, next) => {
    // Chỉ verify reCAPTCHA cho các route đăng ký và đăng nhập
    if (req.path === "/auth/register" || req.path === "/auth/login") {
        try {
            const { recaptchaToken } = req.body;

            if (!recaptchaToken) {
                return res.status(400).json({
                    message: "Thiếu reCAPTCHA token",
                    code: "MISSING_RECAPTCHA"
                });
            }

            // Kiểm tra độ dài token
            if (recaptchaToken.length < 10 || recaptchaToken.length > 1000) {
                return res.status(400).json({
                    message: "Token reCAPTCHA không hợp lệ",
                    code: "INVALID_RECAPTCHA_TOKEN"
                });
            }

            console.log("Verifying reCAPTCHA...");

            const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `secret=${RECAPTCHA_SECRET_KEY}&response=${recaptchaToken}`
            });

            const data = await response.json();
            console.log("reCAPTCHA verification response:", data);

            if (!data.success) {
                const errorCodes = data["error-codes"] || [];
                console.log("reCAPTCHA verification failed. Error codes:", errorCodes);
                return res.status(400).json({
                    message: "Xác thực bảo mật thất bại",
                    code: "RECAPTCHA_FAILED",
                    error: errorCodes
                });
            }

            // Kiểm tra score nếu dùng reCAPTCHA v3
            if (data.score && data.score < 0.5) {
                return res.status(400).json({
                    message: "Xác thực bảo mật không đạt yêu cầu",
                    code: "RECAPTCHA_LOW_SCORE",
                    score: data.score
                });
            }

            console.log("reCAPTCHA verification successful");
            next();
        } catch (error) {
            console.error("reCAPTCHA verification error:", error);
            return res.status(500).json({
                message: "Lỗi xác thực bảo mật",
                code: "RECAPTCHA_SERVER_ERROR"
            });
        }
    } else {
        // Skip reCAPTCHA for other routes
        next();
    }
};