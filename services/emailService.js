// secure-backend/services/emailService.js
import { Resend } from "resend";
import dotenv from "dotenv";

dotenv.config();

export const resend = new Resend(process.env.RESEND_API_KEY);

// HTML template email
function loginAlertTemplate(username, time, ip, browser) {
    return `
    <div style="font-family: Arial; padding: 20px;">
      <h2>🔐 Cảnh báo đăng nhập</h2>
      <p>Tài khoản <b>${username}</b> vừa đăng nhập vào hệ thống.</p>
      <p><b>Thời gian:</b> ${time}</p>
      <p><b>Địa chỉ IP:</b> ${ip}</p>
      <p><b>Trình duyệt:</b> ${browser}</p>
      <br>
      <p>Nếu không phải bạn, hãy đổi mật khẩu ngay.</p>
    </div>
  `;
}

class EmailService {
    async sendLoginAlert(email, username, loginData) {
        if (!process.env.RESEND_API_KEY) {
            console.log("❌ RESEND_API_KEY missing");
            return { success: false };
        }

        if (!process.env.EMAIL_FROM) {
            console.log("❌ EMAIL_FROM missing");
            return { success: false };
        }

        const html = loginAlertTemplate(
            username,
            loginData.loginTime,
            loginData.ip,
            loginData.browser
        );

        try {
            console.log(`📧 Sending Resend alert → ${email}`);

            const result = await resend.emails.send({
                from: process.env.EMAIL_FROM,
                to: email,
                subject: `🔐 Login Alert - ${username}`,
                html,
            });

            return { success: true, id: result.id };
        } catch (err) {
            console.error("❌ Resend sendLoginAlert error:", err);
            return { success: false, error: err.message };
        }
    }
}

export const emailService = new EmailService();
