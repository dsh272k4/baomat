import { Resend } from 'resend';
import dotenv from 'dotenv';

dotenv.config();

// Khởi tạo Resend instance
export const resend = new Resend(process.env.RESEND_API_KEY);

// Domain bạn đã verify trong Resend
const FROM_EMAIL = process.env.RESEND_FROM_EMAIL || 'security@dta2k4.shop';

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

export const getOTPEmailTemplate = (username, otpCode) => {
    return `
    <html>
        <body style="font-family: Arial; background: #f6f6f6; padding: 20px;">
            <div style="max-width:600px; margin:auto; background:#ffffff; padding:30px; border-radius:10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <div style="text-align: center; margin-bottom: 20px;">
                    <h2 style="color: #3b82f6; margin: 0;">🔐 Mã Xác Thực OTP</h2>
                </div>
                
                <p>Xin chào <b>${username}</b>,</p>
                
                <p>Bạn đang thực hiện đăng nhập vào tài khoản. Vui lòng sử dụng mã OTP dưới đây để hoàn tất xác thực:</p>
                
                <div style="text-align: center; margin: 30px 0;">
                    <div style="font-size: 32px; font-weight: bold; color: #3b82f6; letter-spacing: 5px; background: #f8fafc; padding: 15px; border-radius: 8px; border: 2px dashed #e2e8f0;">
                        ${otpCode}
                    </div>
                </div>
                
                <div style="background: #fff3cd; padding: 15px; border-radius: 6px; border: 1px solid #ffeaa7; margin: 20px 0;">
                    <p style="margin: 0; color: #856404;">
                        <b>⚠️ Lưu ý quan trọng:</b><br>
                        • Mã OTP có hiệu lực trong <b>10 phút</b><br>
                        • Không chia sẻ mã này với bất kỳ ai<br>
                        • Nếu bạn không yêu cầu mã này, vui lòng bỏ qua email
                    </p>
                </div>
                
                <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 25px 0;">
                
                <p style="color: #6c757d; font-size: 12px; text-align: center;">
                    Đây là email tự động, vui lòng không trả lời.<br>
                    Nếu bạn gặp vấn đề, hãy liên hệ với quản trị viên.
                </p>
            </div>
        </body>
    </html>
    `;
};

// Export từ email cho Resend
export const FROM_EMAIL = FROM_EMAIL;