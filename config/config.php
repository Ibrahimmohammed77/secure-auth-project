<?php
// إعدادات الأمان والتطبيق
return [
    // إعدادات قاعدة البيانات
    'database' => [
        'host' => 'localhost',
        'name' => 'secure_auth_db',
        'username' => 'root',
        'password' => '',
        'charset' => 'utf8mb4'
    ],
    
    // إعدادات الأمان
    'security' => [
        'bcrypt_cost' => 12,
        'token_expiry' => 3600, // ثانية واحدة
        'session_timeout' => 86400, // 24 ساعة
        'max_login_attempts' => 5,
        'lockout_time' => 900, // 15 دقيقة
        'min_password_length' => 8,
        'require_mfa_teachers' => true
    ],
    
    // إعدادات التطبيق
    'app' => [
        'name' => 'نظام التعليم الإلكتروني',
        'url' => 'http://localhost/secure-auth-project',
        'timezone' => 'Asia/Riyadh',
        'debug' => true
    ],
    
    // إعدادات البريد الإلكتروني
    'email' => [
        'smtp_host' => 'smtp.gmail.com',
        'smtp_port' => 587,
        'smtp_username' => '',
        'smtp_password' => '',
        'from_email' => 'noreply@yourdomain.com',
        'from_name' => 'نظام التعليم الإلكتروني'
    ],
    
    // إعدادات الجلسة
    'session' => [
        'cookie_lifetime' => 86400,
        'cookie_secure' => false, // ضع true في الإنتاج
        'cookie_httponly' => true,
        'cookie_samesite' => 'Strict'
    ]
];
?>