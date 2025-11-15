import { createTransporter, getLoginAlertTemplate } from '../config/emailConfig.js';

export class EmailService {
    constructor() {
        this.transporter = createTransporter();
        this.isEnabled = !!this.transporter;
    }

    // Kiểm tra kết nối email với timeout
    async verifyConnection() {
        if (!this.isEnabled) {
            console.log('⚠️ Email service disabled - no configuration');
            return false;
        }

        try {
            // Thêm timeout cho connection verification
            const timeoutPromise = new Promise((_, reject) => {
                setTimeout(() => reject(new Error('Connection timeout')), 10000);
            });

            const verifyPromise = this.transporter.verify();
            await Promise.race([verifyPromise, timeoutPromise]);

            console.log('✅ Email server connection verified');
            return true;
        } catch (error) {
            console.log('❌ Email server connection failed:', error.message);
            this.isEnabled = false; // Tắt email service nếu không kết nối được
            return false;
        }
    }

    // Gửi email thông báo đăng nhập với error handling tốt hơn
    async sendLoginAlert(userEmail, username, loginData) {
        // Kiểm tra xem email service có enabled không
        if (!this.isEnabled) {
            console.log('⚠️ Email service disabled - skipping email send');
            return { success: false, error: 'Email service disabled' };
        }

        // Kiểm tra email có hợp lệ không
        if (!userEmail || !userEmail.includes('@')) {
            console.log('⚠️ Invalid email address:', userEmail);
            return { success: false, error: 'Invalid email address' };
        }

        try {
            const { ip, browser, loginTime } = loginData;

            const mailOptions = {
                from: `"Hệ thống Bảo mật" <${process.env.EMAIL_USER}>`,
                to: userEmail,
                subject: `🔐 Thông báo đăng nhập - ${username}`,
                html: getLoginAlertTemplate(username, loginTime, ip, browser),
                // Thêm headers để tránh bị mark là spam
                headers: {
                    'X-Priority': '3',
                    'X-MSMail-Priority': 'Normal',
                    'Importance': 'Normal'
                }
            };

            console.log(`📧 Attempting to send login alert to: ${userEmail}`);

            // Thêm timeout cho việc gửi email
            const sendPromise = this.transporter.sendMail(mailOptions);
            const timeoutPromise = new Promise((_, reject) => {
                setTimeout(() => reject(new Error('Send email timeout')), 15000);
            });

            const result = await Promise.race([sendPromise, timeoutPromise]);

            console.log(`✅ Login alert email sent to ${userEmail}:`, result.messageId);
            return { success: true, messageId: result.messageId };
        } catch (error) {
            console.error('❌ Error sending login alert email:', error.message);

            // Nếu lỗi kết nối, disable email service
            if (error.code === 'ETIMEDOUT' || error.code === 'ECONNREFUSED') {
                console.log('🚫 Disabling email service due to connection issues');
                this.isEnabled = false;
            }

            return {
                success: false,
                error: error.message,
                code: error.code
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

// Tạo instance
export const emailService = new EmailService();

// Kiểm tra kết nối email khi khởi động (không block startup)
setTimeout(() => {
    emailService.verifyConnection().then(success => {
        if (success) {
            console.log('🚀 Email service ready');
        } else {
            console.log('⚠️ Email service not available - emails will be skipped');
        }
    });
}, 3000); // Delay 3 giây để server khởi động xong