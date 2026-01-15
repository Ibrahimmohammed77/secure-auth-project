<?php
session_start();
require_once 'includes/Auth.php';

$auth = new Auth();

// التحقق من الجلسة
if (!isset($_COOKIE['session_token'])) {
    header('Location: login.php');
    exit;
}

$user = $auth->validateSession($_COOKIE['session_token']);
if (!$user) {
    header('Location: login.php');
    exit;
}

// معالجة تسجيل الخروج
if (isset($_POST['logout'])) {
    $auth->logout($_COOKIE['session_token']);
    header('Location: index.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>لوحة التحكم - نظام التعليم الإلكتروني</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Arial', sans-serif;
            background: #f5f7fa;
            color: #333;
        }
        
        .navbar {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        
        .navbar-brand {
            font-size: 1.5rem;
            font-weight: bold;
        }
        
        .user-menu {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        
        .user-info {
            text-align: left;
        }
        
        .user-info .name {
            font-weight: bold;
        }
        
        .user-info .role {
            font-size: 0.9rem;
            opacity: 0.8;
        }
        
        .logout-btn {
            background: rgba(255, 255, 255, 0.2);
            border: none;
            color: white;
            padding: 10px 20px;
            border-radius: 50px;
            cursor: pointer;
            transition: background 0.3s;
        }
        
        .logout-btn:hover {
            background: rgba(255, 255, 255, 0.3);
        }
        
        .container {
            max-width: 1200px;
            margin: 40px auto;
            padding: 0 20px;
        }
        
        .welcome-section {
            background: white;
            border-radius: 15px;
            padding: 40px;
            margin-bottom: 30px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
            border-right: 5px solid #667eea;
        }
        
        .welcome-section h1 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .welcome-section p {
            color: #666;
            font-size: 1.1rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
            text-align: center;
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card .icon {
            font-size: 2.5rem;
            margin-bottom: 15px;
        }
        
        .stat-card .value {
            font-size: 2rem;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 10px;
        }
        
        .stat-card .label {
            color: #666;
            font-size: 1rem;
        }
        
        .security-section {
            background: white;
            border-radius: 15px;
            padding: 40px;
            margin-bottom: 30px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
        }
        
        .security-section h2 {
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #f0f0f0;
        }
        
        .security-status {
            display: flex;
            align-items: center;
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .status-indicator {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            background: #4CAF50;
        }
        
        .status-indicator.warning {
            background: #ff9800;
        }
        
        .status-indicator.danger {
            background: #f44336;
        }
        
        .security-actions {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        
        .security-btn {
            padding: 15px;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }
        
        .security-btn-primary {
            background: #667eea;
            color: white;
        }
        
        .security-btn-primary:hover {
            background: #5a6fd8;
        }
        
        .security-btn-secondary {
            background: #f0f0f0;
            color: #333;
        }
        
        .security-btn-secondary:hover {
            background: #e0e0e0;
        }
        
        .recent-activity {
            background: white;
            border-radius: 15px;
            padding: 40px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
        }
        
        .activity-list {
            margin-top: 20px;
        }
        
        .activity-item {
            padding: 15px;
            border-bottom: 1px solid #f0f0f0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .activity-item:last-child {
            border-bottom: none;
        }
        
        .activity-time {
            color: #999;
            font-size: 0.9rem;
        }
        
        .mfa-status {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 50px;
            font-size: 0.9rem;
            font-weight: bold;
        }
        
        .mfa-enabled {
            background: #e8f5e9;
            color: #2e7d32;
        }
        
        .mfa-disabled {
            background: #ffebee;
            color: #c62828;
        }
        
        @media (max-width: 768px) {
            .navbar {
                flex-direction: column;
                gap: 15px;
                text-align: center;
            }
            
            .user-info {
                text-align: center;
            }
            
            .container {
                padding: 0 10px;
            }
            
            .welcome-section,
            .security-section,
            .recent-activity {
                padding: 20px;
            }
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="navbar-brand">
            نظام التعليم الإلكتروني الآمن
        </div>
        <div class="user-menu">
            <div class="user-info">
                <div class="name">مرحباً، <?php echo htmlspecialchars($user['email']); ?></div>
                <div class="role">
                    <?php 
                    $roleNames = [
                        'student' => 'طالب',
                        'teacher' => 'مدرس',
                        'admin' => 'مدير النظام'
                    ];
                    echo $roleNames[$user['role']] ?? $user['role'];
                    ?>
                </div>
            </div>
            <form method="POST">
                <button type="submit" name="logout" class="logout-btn">
                    تسجيل الخروج
                </button>
            </form>
        </div>
    </nav>
    
    <div class="container">
        <div class="welcome-section">
            <h1>مرحباً بك في لوحة التحكم</h1>
            <p>آخر دخول: <?php echo $user['last_login_at'] ? date('Y-m-d H:i:s', strtotime($user['last_login_at'])) : 'أول دخول'; ?></p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="icon">👨‍🎓</div>
                <div class="value">50,000+</div>
                <div class="label">طالب مسجل</div>
            </div>
            
            <div class="stat-card">
                <div class="icon">👨‍🏫</div>
                <div class="value">2,000+</div>
                <div class="label">مدرس معتمد</div>
            </div>
            
            <div class="stat-card">
                <div class="icon">📚</div>
                <div class="value">10,000+</div>
                <div class="label">مادة تعليمية</div>
            </div>
            
            <div class="stat-card">
                <div class="icon">🏆</div>
                <div class="value">99.9%</div>
                <div class="label">معدل الأمان</div>
            </div>
        </div>
        
        <div class="security-section">
            <h2>🔒 حالة الأمان لحسابك</h2>
            
            <div class="security-status">
                <div class="status-indicator <?php echo $user['mfa_enabled'] ? '' : 'warning'; ?>"></div>
                <div>
                    <h3>المصادقة الثنائية</h3>
                    <p>
                        <?php if ($user['mfa_enabled']): ?>
                            <span class="mfa-status mfa-enabled">مفعلة ✓</span>
                        <?php else: ?>
                            <span class="mfa-status mfa-disabled">غير مفعلة ✗</span>
                            - نوصي بتفعيلها للحماية القصوى
                        <?php endif; ?>
                    </p>
                </div>
            </div>
            
            <div class="security-actions">
                <?php if (!$user['mfa_enabled']): ?>
                    <button class="security-btn security-btn-primary" onclick="window.location.href='enable-mfa.php'">
                        🔐 تفعيل المصادقة الثنائية
                    </button>
                <?php endif; ?>
                
                <button class="security-btn security-btn-secondary" onclick="window.location.href='change-password.php'">
                    🔑 تغيير كلمة المرور
                </button>
                
                <button class="security-btn security-btn-secondary" onclick="window.location.href='security-logs.php'">
                    📊 سجل الأمان
                </button>
                
                <button class="security-btn security-btn-secondary" onclick="window.location.href='sessions.php'">
                    💻 الجلسات النشطة
                </button>
            </div>
        </div>
        
        <div class="recent-activity">
            <h2>📋 آخر الأنشطة</h2>
            <div class="activity-list">
                <div class="activity-item">
                    <span>✅ تسجيل الدخول الناجح</span>
                    <span class="activity-time">الآن</span>
                </div>
                <div class="activity-item">
                    <span>📍 الدخول من <?php echo htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? 'جهاز غير معروف'); ?></span>
                    <span class="activity-time">الآن</span>
                </div>
                <div class="activity-item">
                    <span>📱 جهاز: <?php echo htmlspecialchars(substr($_SERVER['HTTP_USER_AGENT'] ?? 'جهاز غير معروف', 0, 50)); ?></span>
                    <span class="activity-time">الآن</span>
                </div>
                <?php if ($user['last_login_at']): ?>
                <div class="activity-item">
                    <span>⏰ آخر دخول سابق</span>
                    <span class="activity-time"><?php echo date('Y-m-d H:i:s', strtotime($user['last_login_at'])); ?></span>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <script>
        // تحديث وقت الدخول تلقائياً
        function updateLoginTime() {
            const now = new Date();
            const timeString = now.toLocaleString('ar-SA', {
                year: 'numeric',
                month: 'long',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
            
            const timeElements = document.querySelectorAll('.activity-time');
            if (timeElements[0]) {
                timeElements[0].textContent = timeString;
            }
        }
        
        // تحديث كل دقيقة
        setInterval(updateLoginTime, 60000);
        
        // تأكيد تسجيل الخروج
        document.querySelector('form').addEventListener('submit', function(e) {
            if (e.submitter && e.submitter.name === 'logout') {
                if (!confirm('هل أنت متأكد من تسجيل الخروج؟')) {
                    e.preventDefault();
                }
            }
        });
    </script>
</body>
</html>