import DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

const window = new JSDOM('').window;
const domPurify = DOMPurify(window);

// Tạo hàm sanitize cho các loại dữ liệu
export const xssSanitizer = {
    // Sanitize string
    sanitizeString: (input) => {
        if (typeof input !== 'string') return input;
        return domPurify.sanitize(input.trim());
    },

    // Sanitize object recursively
    sanitizeObject: (obj) => {
        if (!obj || typeof obj !== 'object') return obj;

        const sanitized = Array.isArray(obj) ? [] : {};

        for (const key in obj) {
            if (Object.prototype.hasOwnProperty.call(obj, key)) {
                const value = obj[key];

                if (typeof value === 'string') {
                    sanitized[key] = domPurify.sanitize(value.trim());
                } else if (typeof value === 'object' && value !== null) {
                    sanitized[key] = xssSanitizer.sanitizeObject(value);
                } else {
                    sanitized[key] = value;
                }
            }
        }

        return sanitized;
    },

    // Sanitize HTML content (cho phép một số tag an toàn)
    sanitizeHTML: (html) => {
        if (typeof html !== 'string') return html;

        return domPurify.sanitize(html, {
            ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'],
            ALLOWED_ATTR: ['class', 'style']
        });
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

// Middleware cho các route cụ thể
export const strictXSSMiddleware = (req, res, next) => {
    const blacklist = [
        '<script>', '</script>', 'javascript:', 'onload=', 'onerror=',
        'onclick=', 'onmouseover=', 'eval(', 'alert(', 'document.cookie',
        'window.location', 'innerHTML', 'outerHTML'
    ];

    const checkForXSS = (obj) => {
        for (const key in obj) {
            if (typeof obj[key] === 'string') {
                const value = obj[key].toLowerCase();
                if (blacklist.some(pattern => value.includes(pattern))) {
                    return true;
                }
            } else if (typeof obj[key] === 'object' && obj[key] !== null) {
                if (checkForXSS(obj[key])) return true;
            }
        }
        return false;
    };

    if ([req.query, req.body, req.params].some(checkForXSS)) {
        return res.status(400).json({
            message: "Request chứa nội dung nguy hiểm",
            code: "XSS_ATTACK_DETECTED"
        });
    }

    next();
};