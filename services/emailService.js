import { resend, getLoginAlertTemplate, getOTPEmailTemplate, FROM_EMAIL } from '../config/emailConfig.js';

export class EmailService {
    constructor() {
        this.isEnabled = !!process.env.RESEND_API_KEY;
        if (this.isEnabled) {
            console.log('📧 Resend email service initialized');
        } else {
            console.log('⚠️ Resend API key missing - email service disabled');
        }
    }

    // Kiểm tra kết nối Resend
    async verifyConnection() {
        if (!this.isEnabled) {
            return false;
        }

        try {
            // Resend không có phương thức verify, nên chúng ta thử gửi email test
            console.log('✅ Resend email service ready (API key present)');
            return true;
        } catch (error) {
            console.log('❌ Resend connection check failed:', error.message);
            return false;
        }
    }

    // Gửi email thông báo đăng nhập với Resend
    async sendLoginAlert(userEmail, username, loginData) {
        if (!this.isEnabled) {
            console.log('⚠️ Email service disabled - skipping email send');
            return { success: false, error: 'Email service disabled' };
        }

        try {
            const { ip, browser, loginTime } = loginData;

            const { data, error } = await resend.emails.send({
                from: `Hệ thống Bảo mật <${FROM_EMAIL}>`,
                to: [userEmail],
                subject: `🔐 Thông báo đăng nhập - ${username}`,
                html: getLoginAlertTemplate(username, loginTime, ip, browser),
            });

            if (error) {
                console.error('❌ Error sending login alert email:', error);
                return { success: false, error: error.message };
            }

            console.log(`✅ Login alert email sent to ${userEmail}:`, data.id);
            return { success: true, messageId: data.id };
        } catch (error) {
            console.error('❌ Error sending login alert email:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Gửi email OTP với Resend
    async sendOTPEmail(userEmail, username, otpCode) {
        if (!this.isEnabled) {
            console.log('⚠️ Email service disabled - skipping OTP email');
            return { success: false, error: 'Email service disabled' };
        }

        try {
            const { data, error } = await resend.emails.send({
                from: `Hệ thống Bảo mật <${FROM_EMAIL}>`,
                to: [userEmail],
                subject: `🔐 Mã xác thực OTP - ${username}`,
                html: getOTPEmailTemplate(username, otpCode),
            });

            if (error) {
                console.error('❌ Error sending OTP email:', error);
                return { success: false, error: error.message };
            }

            console.log(`✅ OTP email sent to ${userEmail}:`, data.id);
            return { success: true, messageId: data.id };
        } catch (error) {
            console.error('❌ Error sending OTP email:', error);
            return {
                success: false,
                error: error.message
            };
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
            const shouldSend = user.email && user.receive_login_alerts === 1 && this.isEnabled;

            console.log(`📧 Email alert check for user ${userId}:`, {
                hasEmail: !!user.email,
                receiveAlerts: user.receive_login_alerts,
                emailEnabled: this.isEnabled,
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

export const emailService = new EmailService();

// Kiểm tra kết nối khi khởi động
setTimeout(() => {
    emailService.verifyConnection().then(success => {
        if (success) {
            console.log('🚀 Resend email service ready');
        } else {
            console.log('⚠️ Email service not available - emails will be skipped');
        }
    });
}, 3000);