// secure-backend/middleware/recaptcha.js
import dotenv from "dotenv";
dotenv.config();

const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY || "6Lf5aewrAAAAALpWLmRPTqwYTS_w7WCz4xR8-k7z";

export const verifyRecaptcha = async (req, res, next) => {
    // Chỉ verify reCAPTCHA cho các route đăng ký và đăng nhập
    if (req.path === "/auth/register" || req.path === "/auth/login") {
        try {
            const { recaptchaToken } = req.body;

            if (!recaptchaToken) {
                return res.status(400).json({ message: "Thiếu reCAPTCHA token. Vui lòng xác thực bạn không phải là robot." });
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
                    message: "Xác thực bảo mật thất bại. Vui lòng thử lại.",
                    error: errorCodes
                });
            }

            // reCAPTCHA passed, continue to next middleware
            console.log("reCAPTCHA verification successful");
            next();
        } catch (error) {
            console.error("reCAPTCHA verification error:", error);
            return res.status(500).json({ message: "Lỗi xác thực bảo mật. Vui lòng thử lại sau." });
        }
    } else {
        // Skip reCAPTCHA for other routes
        next();
    }
};