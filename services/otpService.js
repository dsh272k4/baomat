import { emailService } from './emailService.js';
import { pool } from '../config/db.js';

export class OTPService {
    constructor() {
        this.otpExpiryMinutes = 10; // OTP hết hạn sau 10 phút
    }

    // Tạo mã OTP 6 chữ số
    generateOTP() {
        return Math.floor(100000 + Math.random() * 900000).toString();
    }

    // Lưu OTP vào database
    async saveOTP(userId, otpCode) {
        try {
            const expiresAt = new Date(Date.now() + this.otpExpiryMinutes * 60 * 1000);

            await pool.query(
                `INSERT INTO user_otps (user_id, otp_code, expires_at, used) 
                 VALUES (?, ?, ?, 0) 
                 ON DUPLICATE KEY UPDATE 
                 otp_code = ?, expires_at = ?, used = 0, created_at = NOW()`,
                [userId, otpCode, expiresAt, otpCode, expiresAt]
            );

            console.log(`✅ OTP saved for user ${userId}: ${otpCode}`);
            return true;
        } catch (error) {
            console.error('❌ Error saving OTP:', error);
            return false;
        }
    }

    // Kiểm tra OTP
    async verifyOTP(userId, otpCode) {
        try {
            const [rows] = await pool.query(
                `SELECT id, otp_code, expires_at, used 
                 FROM user_otps 
                 WHERE user_id = ? AND otp_code = ? AND used = 0`,
                [userId, otpCode]
            );

            if (rows.length === 0) {
                return { isValid: false, message: "Mã OTP không tồn tại hoặc đã được sử dụng" };
            }

            const otpRecord = rows[0];
            const now = new Date();

            if (now > new Date(otpRecord.expires_at)) {
                return { isValid: false, message: "Mã OTP đã hết hạn" };
            }

            // Đánh dấu OTP đã sử dụng
            await pool.query(
                'UPDATE user_otps SET used = 1 WHERE id = ?',
                [otpRecord.id]
            );

            console.log(`✅ OTP verified for user ${userId}`);
            return { isValid: true, message: "Xác thực OTP thành công" };
        } catch (error) {
            console.error('❌ Error verifying OTP:', error);
            return { isValid: false, message: "Lỗi xác thực OTP" };
        }
    }

    // Gửi OTP qua email
    async sendOTPEmail(userEmail, username, otpCode) {
        return await emailService.sendOTPEmail(userEmail, username, otpCode);
    }

    // Kiểm tra xem user có cần OTP không
    async shouldRequireOTP(userId) {
        // Luôn yêu cầu OTP cho mọi lần đăng nhập
        return true;
    }

    // Xóa OTP hết hạn
    async cleanupExpiredOTPs() {
        try {
            const result = await pool.query(
                'DELETE FROM user_otps WHERE expires_at < NOW() OR used = 1'
            );
            console.log(`🧹 Cleaned up ${result[0].affectedRows} expired OTPs`);
        } catch (error) {
            console.error('Error cleaning up OTPs:', error);
        }
    }
}

export const otpService = new OTPService();

// Clean up OTPs mỗi 30 phút
setInterval(() => {
    otpService.cleanupExpiredOTPs();
}, 30 * 60 * 1000);