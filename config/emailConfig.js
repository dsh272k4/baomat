// secure-backend/config/emailConfig.js
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

// Cấu hình email transporter - SỬA LẠI THÀNH createTransport
export const createTransporter = () => {
    return nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD
        }
    });
};

// Template email thông báo đăng nhập
export const getLoginAlertTemplate = (username, loginTime, ip, browser) => {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #3b82f6; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
            .content { background: #f8fafc; padding: 20px; border-radius: 0 0 8px 8px; }
            .alert { background: #fee2e2; color: #dc2626; padding: 10px; border-radius: 4px; margin: 10px 0; }
            .info-box { background: white; padding: 15px; border-radius: 4px; margin: 10px 0; border-left: 4px solid #3b82f6; }
            .footer { text-align: center; margin-top: 20px; color: #6b7280; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔐 Thông báo Đăng nhập</h1>
            </div>
            <div class="content">
                <div class="alert">
                    <strong>⚠️ CẢNH BÁO BẢO MẬT</strong>
                </div>
                
                <p>Xin chào <strong>${username}</strong>,</p>
                
                <p>Chúng tôi vừa ghi nhận một lần đăng nhập vào tài khoản của bạn:</p>
                
                <div class="info-box">
                    <strong>📋 Thông tin đăng nhập:</strong><br>
                    👤 Tài khoản: <strong>${username}</strong><br>
                    🕐 Thời gian: <strong>${loginTime}</strong><br>
                    🌐 Địa chỉ IP: <strong>${ip}</strong><br>
                    🔍 Trình duyệt: <strong>${browser}</strong>
                </div>

                <p>Nếu đây là bạn, bạn có thể bỏ qua email này.</p>
                
                <p>Nếu bạn không thực hiện đăng nhập này, vui lòng:</p>
                <ul>
                    <li>Thay đổi mật khẩu ngay lập tức</li>
                    <li>Kiểm tra các hoạt động đáng ngờ khác</li>
                    <li>Liên hệ với quản trị viên nếu cần</li>
                </ul>
            </div>
            <div class="footer">
                <p>Email này được gửi tự động từ hệ thống bảo mật.<br>
                Vui lòng không trả lời email này.</p>
            </div>
        </div>
    </body>
    </html>
  `;
};