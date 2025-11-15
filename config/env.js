// config/env.js
export const validateEnv = () => {
    const required = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'JWT_SECRET'];
    const missing = required.filter(key => !process.env[key]);
    if (missing.length) {
        throw new Error(`Missing env variables: ${missing.join(', ')}`);
    }
};