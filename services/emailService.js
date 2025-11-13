import { createTransporter, getLoginAlertTemplate } from '../config/emailConfig.js';

export class EmailService {
    constructor() {
        this.transporter = createTransporter();
    }

    // Kiểm tra kết nối email
    async verifyConnection() {
        try {
            await this.transporter.verify();
            console.log('✅ Email server connection verified');
            return true;
        } catch (error) {
            console.error('❌ Email server connection failed:', error);
            return false;
        }
    }

    // Gửi email thông báo đăng nhập
    async sendLoginAlert(userEmail, username, loginData) {
        // Kiểm tra xem có cấu hình email không
        if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
            console.log('⚠️ Email configuration missing - skipping email send');
            return { success: false, error: 'Email configuration missing' };
        }

        try {
            const { ip, browser, loginTime } = loginData;

            const mailOptions = {
                from: `"Hệ thống Bảo mật" <${process.env.EMAIL_USER}>`,
                to: userEmail,
                subject: `🔐 Thông báo đăng nhập - ${username}`,
                html: getLoginAlertTemplate(username, loginTime, ip, browser)
            };

            console.log(`📧 Attempting to send login alert to: ${userEmail}`);

            const result = await this.transporter.sendMail(mailOptions);
            console.log(`✅ Login alert email sent to ${userEmail}:`, result.messageId);
            return { success: true, messageId: result.messageId };
        } catch (error) {
            console.error('❌ Error sending login alert email:', error);
            return { success: false, error: error.message };
        }
    }

    // Kiểm tra xem user có email và muốn nhận thông báo không
    async shouldSendLoginAlert(userId, pool) {
        try {
            const [rows] = await pool.query(
                'SELECT email, receive_login_alerts FROM users WHERE id = ?',
                [userId]
            );

            if (rows.length === 0) return { shouldSend: false, email: null };

            const user = rows[0];
            const shouldSend = user.email && user.receive_login_alerts === 1;

            console.log(`📧 Email alert check for user ${userId}:`, {
                hasEmail: !!user.email,
                receiveAlerts: user.receive_login_alerts,
                shouldSend
            });

            return {
                shouldSend,
                email: user.email
            };
        } catch (error) {
            console.error('Error checking login alert preference:', error);
            return { shouldSend: false, email: null };
        }
    }
}

// Tạo instance và kiểm tra kết nối
export const emailService = new EmailService();

// Kiểm tra kết nối email khi khởi động (không block startup)
emailService.verifyConnection().then(success => {
    if (success) {
        console.log('🚀 Email service ready');
    } else {
        console.log('⚠️ Email service not available - emails will be skipped');
    }
})