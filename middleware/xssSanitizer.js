import DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

const window = new JSDOM('').window;
const domPurify = DOMPurify(window);

// Hàm sanitize cho các loại dữ liệu
export const xssSanitizer = {
    // Sanitize string - STRICTER VERSION
    sanitizeString: (input) => {
        if (typeof input !== 'string') return input;

        // Loại bỏ hoàn toàn các thẻ HTML và script
        const sanitized = domPurify.sanitize(input, {
            ALLOWED_TAGS: [], // KHÔNG cho phép bất kỳ tag nào
            ALLOWED_ATTR: []  // KHÔNG cho phép bất kỳ attribute nào
        });

        // Thêm biện pháp phòng thủ: escape các ký tự đặc biệt
        return sanitized
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
    },

    // Sanitize object recursively
    sanitizeObject: (obj) => {
        if (!obj || typeof obj !== 'object') return obj;

        const sanitized = Array.isArray(obj) ? [] : {};

        for (const key in obj) {
            if (Object.prototype.hasOwnProperty.call(obj, key)) {
                const value = obj[key];

                if (typeof value === 'string') {
                    sanitized[key] = xssSanitizer.sanitizeString(value);
                } else if (typeof value === 'object' && value !== null) {
                    sanitized[key] = xssSanitizer.sanitizeObject(value);
                } else {
                    sanitized[key] = value;
                }
            }
        }

        return sanitized;
    }
};

// Middleware chính để sanitize request data
export const xssMiddleware = (req, res, next) => {
    try {
        // Sanitize query parameters
        if (req.query && Object.keys(req.query).length > 0) {
            req.query = xssSanitizer.sanitizeObject(req.query);
        }

        // Sanitize body parameters
        if (req.body && Object.keys(req.body).length > 0) {
            req.body = xssSanitizer.sanitizeObject(req.body);
        }

        // Sanitize params
        if (req.params && Object.keys(req.params).length > 0) {
            req.params = xssSanitizer.sanitizeObject(req.params);
        }

        next();
    } catch (error) {
        console.error('XSS Sanitization error:', error);
        res.status(400).json({
            message: "Dữ liệu không hợp lệ",
            code: "INVALID_INPUT"
        });
    }
};

// Middleware strict XSS check - STRICTER VERSION
export const strictXSSMiddleware = (req, res, next) => {
    const blacklist = [
        '<script', '</script', 'javascript:', 'onload=', 'onerror=',
        'onclick=', 'onmouseover=', 'eval(', 'alert(', 'document.cookie',
        'window.location', 'innerHTML', 'outerHTML', '<iframe', '<img',
        '<svg', 'onload'
    ];

    const checkForXSS = (obj, path = '') => {
        for (const key in obj) {
            if (Object.prototype.hasOwnProperty.call(obj, key)) {
                const currentPath = path ? `${path}.${key}` : key;

                if (typeof obj[key] === 'string') {
                    const value = obj[key].toLowerCase();

                    // Kiểm tra blacklist patterns
                    const foundPattern = blacklist.find(pattern => value.includes(pattern));
                    if (foundPattern) {
                        console.log(`XSS detected in ${currentPath}: ${foundPattern} in "${obj[key]}"`);
                        return true;
                    }

                    // Kiểm tra các ký tự HTML/script cơ bản
                    if (/<[a-z][\s\S]*>/i.test(obj[key]) || /script/i.test(obj[key])) {
                        console.log(`HTML/SCRIPT tag detected in ${currentPath}: "${obj[key]}"`);
                        return true;
                    }
                } else if (typeof obj[key] === 'object' && obj[key] !== null) {
                    if (checkForXSS(obj[key], currentPath)) return true;
                }
            }
        }
        return false;
    };

    // Kiểm tra tất cả các phần của request
    const hasXSS = [req.query, req.body, req.params].some(checkForXSS);

    if (hasXSS) {
        console.log('🚨 XSS Attack Blocked:', {
            ip: req.ip,
            method: req.method,
            path: req.path,
            body: req.body
        });

        return res.status(400).json({
            message: "Dữ liệu chứa nội dung nguy hiểm. Vui lòng kiểm tra lại.",
            code: "XSS_ATTACK_DETECTED"
        });
    }

    next();
};