<?php
session_start();
require_once 'includes/Auth.php';

// التحقق من الجلسة
$auth = new Auth();
$user = null;

if (isset($_COOKIE['session_token'])) {
    $user = $auth->validateSession($_COOKIE['session_token']);
}

if ($user) {
    header('Location: dashboard.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>نظام التعليم الإلكتروني الآمن</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Arial', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        
        .container {
            width: 100%;
            max-width: 1200px;
        }
        
        .header {
            text-align: center;
            color: white;
            margin-bottom: 40px;
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.2rem;
            opacity: 0.9;
        }
        
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .feature-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 30px;
            color: white;
            transition: transform 0.3s;
        }
        
        .feature-card:hover {
            transform: translateY(-5px);
        }
        
        .feature-card h3 {
            margin-bottom: 15px;
            font-size: 1.5rem;
        }
        
        .feature-card ul {
            list-style: none;
        }
        
        .feature-card li {
            margin-bottom: 10px;
            padding-right: 20px;
            position: relative;
        }
        
        .feature-card li:before {
            content: '✓';
            position: absolute;
            right: 0;
            color: #4CAF50;
            font-weight: bold;
        }
        
        .auth-buttons {
            text-align: center;
        }
        
        .btn {
            display: inline-block;
            padding: 15px 40px;
            margin: 10px;
            border-radius: 50px;
            text-decoration: none;
            font-weight: bold;
            font-size: 1.1rem;
            transition: all 0.3s;
            border: 2px solid white;
        }
        
        .btn-primary {
            background: white;
            color: #667eea;
        }
        
        .btn-secondary {
            background: transparent;
            color: white;
        }
        
        .btn:hover {
            transform: scale(1.05);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
        }
        
        .security-badge {
            text-align: center;
            margin-top: 30px;
            color: white;
            opacity: 0.8;
        }
        
        @media (max-width: 768px) {
            .features {
                grid-template-columns: 1fr;
            }
            
            .btn {
                display: block;
                margin: 10px auto;
                width: 80%;
                max-width: 300px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>نظام التعليم الإلكتروني الآمن</h1>
            <p>منصة تعليمية محمية بأحدث تقنيات الأمان</p>
        </div>
        
        <div class="features">
            <div class="feature-card">
                <h3>🔐 أمن متقدم</h3>
                <ul>
                    <li>تشفير كلمات المرور بـ bcrypt</li>
                    <li>مصادقة ثنائية العوامل</li>
                    <li>حماية من هجمات Brute Force</li>
                    <li>جلسات آمنة ومشفرة</li>
                    <li>مراقبة الأنشطة المشبوهة</li>
                </ul>
            </div>
            
            <div class="feature-card">
                <h3>👨‍🎓 مخصص للتعليم</h3>
                <ul>
                    <li>إدارة الفصول الدراسية</li>
                    <li>توزيع المواد التعليمية</li>
                    <li>نظام الاختبارات الآمن</li>
                    <li>تواصل آمن مع المدرسين</li>
                    <li>تتبع التقدم الدراسي</li>
                </ul>
            </div>
            
            <div class="feature-card">
                <h3>📊 إحصائيات حية</h3>
                <ul>
                    <li>50,000+ طالب مسجل</li>
                    <li>2,000+ مدرس معتمد</li>
                    <li>10,000+ مادة تعليمية</li>
                    <li>99.9% وقت تشغيل</li>
                    <li>دعم فني 24/7</li>
                </ul>
            </div>
        </div>
        
        <div class="auth-buttons">
            <a href="login.php" class="btn btn-primary">تسجيل الدخول</a>
            <a href="register.php" class="btn btn-secondary">إنشاء حساب جديد</a>
        </div>
        
        <div class="security-badge">
            <p>⛓️ نظامنا يستخدم تشفير عسكري مستوى AES-256</p>
            <p>🔒 جميع الاتصالات مشفرة بـ TLS 1.3</p>
        </div>
    </div>
</body>
</html>