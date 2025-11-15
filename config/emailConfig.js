// secure-backend/config/emailConfig.js
import nodemailer from "nodemailer";
import dotenv from "dotenv";
import { emailService } from "../services/emailService.js";

dotenv.config();

export const createTransporter = () => {
    return nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: Number(process.env.EMAIL_PORT) || 587,
        secure: false,
        requireTLS: true,
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD
        }
    });
};

export const getLoginAlertTemplate = (username, loginTime, ip, browser) => {
    return `
    <html>
        <body style="font-family: Arial; background: #f6f6f6; padding: 20px;">
            <div style="max-width:600px; margin:auto; background:#ffffff; padding:20px; border-radius:8px;">
                <h2>🔐 Thông báo đăng nhập</h2>
                <p>Xin chào <b>${username}</b>,</p>
                <p>Hệ thống vừa ghi nhận một lần đăng nhập:</p>
                <ul>
                    <li><b>Thời gian:</b> ${loginTime}</li>
                    <li><b>IP:</b> ${ip}</li>
                    <li><b>Trình duyệt:</b> ${browser}</li>
                </ul>
                <p>Nếu đây không phải bạn, hãy đổi mật khẩu ngay lập tức.</p>
            </div>
        </body>
    </html>
    `;
};
