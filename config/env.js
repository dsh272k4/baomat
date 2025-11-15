import dotenv from 'dotenv';
dotenv.config();

export const validateEnv = () => {
    const required = [
        'DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME',
        'JWT_SECRET', 'EMAIL_USER', 'EMAIL_PASSWORD',
        'RECAPTCHA_SECRET_KEY'
    ];

    const missing = required.filter(key => !process.env[key]);

    if (missing.length > 0) {
        throw new Error(`❌ Missing required environment variables: ${missing.join(', ')}`);
    }

    // Kiểm tra JWT_SECRET không phải giá trị mặc định
    if (process.env.JWT_SECRET === 'supersecretkey' || process.env.JWT_SECRET.length < 32) {
        throw new Error('❌ JWT_SECRET must be at least 32 characters and not use default value');
    }

    // Kiểm tra RECAPTCHA_SECRET_KEY không phải giá trị mặc định
    if (process.env.RECAPTCHA_SECRET_KEY.includes('6Lf5aewrAAAAALpWLmRPTqwYTS_w7WCz4xR8-k7z')) {
        throw new Error('❌ RECAPTCHA_SECRET_KEY must not use default value');
    }

    console.log('✅ Environment variables validation passed');
};

// Gọi validation khi import
validateEnv();