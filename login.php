<?php
session_start();
require_once 'includes/Auth.php';

// إذا كان المستخدم مسجل دخول بالفعل
if (isset($_COOKIE['session_token'])) {
    $auth = new Auth();
    $user = $auth->validateSession($_COOKIE['session_token']);
    if ($user) {
        header('Location: dashboard.php');
        exit;
    }
}

$auth = new Auth();
$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'];
    $mfa_code = $_POST['mfa_code'] ?? null;
    
    $result = $auth->login($email, $password, $mfa_code);
    
    if ($result['success']) {
        $_SESSION['user'] = $result['user'];
        header('Location: dashboard.php');
        exit;
    } else {
        $error = $result['message'];
        
        // إذا طلب MFA، احتفظ بالبيانات مؤقتًا
        if (isset($result['requires_mfa']) && $result['requires_mfa']) {
            $_SESSION['pending_login'] = [
                'email' => $email,
                'password' => $password
            ];
            header('Location: verify-mfa.php');
            exit;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تسجيل الدخول - نظام التعليم الإلكتروني</title>
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
        
        .login-container {
            width: 100%;
            max-width: 400px;
        }
        
        .login-card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }
        
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .login-header h2 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .login-header p {
            color: #666;
        }
        
        .alert {
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .alert-danger {
            background: #ffebee;
            color: #c62828;
            border: 1px solid #ffcdd2;
        }
        
        .alert-success {
            background: #e8f5e9;
            color: #2e7d32;
            border: 1px solid #c8e6c9;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: bold;
        }
        
        .form-group input {
            width: 100%;
            padding: 15px;
            border: 2px solid #ddd;
            border-radius: 10px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .password-input {
            position: relative;
        }
        
        .toggle-password {
            position: absolute;
            left: 15px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            cursor: pointer;
            font-size: 18px;
        }
        
        .btn {
            width: 100%;
            padding: 15px;
            border: none;
            border-radius: 10px;
            font-size: 18px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
        }
        
        .auth-links {
            text-align: center;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
        
        .auth-links a {
            color: #667eea;
            text-decoration: none;
            margin: 0 10px;
        }
        
        .auth-links a:hover {
            text-decoration: underline;
        }
        
        .security-tips {
            margin-top: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
            border-right: 4px solid #667eea;
        }
        
        .security-tips h4 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .security-tips ul {
            list-style: none;
            padding-right: 20px;
        }
        
        .security-tips li {
            margin-bottom: 8px;
            color: #555;
            position: relative;
        }
        
        .security-tips li:before {
            content: '•';
            color: #667eea;
            font-weight: bold;
            position: absolute;
            right: -15px;
        }
        
        @media (max-width: 480px) {
            .login-card {
                padding: 30px 20px;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-card">
            <div class="login-header">
                <h2>تسجيل الدخول</h2>
                <p>أدخل بياناتك للوصول إلى المنصة التعليمية</p>
            </div>
            
            <?php if ($error): ?>
                <div class="alert alert-danger">
                    <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="alert alert-success">
                    <?php echo htmlspecialchars($success); ?>
                </div>
            <?php endif; ?>
            
            <form method="POST" action="">
                <div class="form-group">
                    <label for="email">البريد الإلكتروني</label>
                    <input type="email" id="email" name="email" required 
                           placeholder="example@domain.com" dir="ltr"
                           value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>">
                </div>
                
                <div class="form-group">
                    <label for="password">كلمة المرور</label>
                    <div class="password-input">
                        <input type="password" id="password" name="password" required 
                               minlength="8" placeholder="********" dir="ltr">
                        <button type="button" class="toggle-password" 
                                onclick="togglePassword()">👁️</button>
                    </div>
                </div>
                
                <button type="submit" class="btn btn-primary">
                    تسجيل الدخول
                </button>
            </form>
            
            <div class="auth-links">
                <a href="forgot-password.php">نسيت كلمة المرور؟</a>
                <span>•</span>
                <a href="register.php">إنشاء حساب جديد</a>
                <span>•</span>
                <a href="index.php">الرئيسية</a>
            </div>
            
            <div class="security-tips">
                <h4>🔒 نصائح أمنية:</h4>
                <ul>
                    <li>تأكد من أن العنوان يبدأ بـ https://</li>
                    <li>لا تشارك بيانات الدخول مع أي شخص</li>
                    <li>تفعيل المصادقة الثنائية للحسابات المهمة</li>
                    <li>احذر من رسائل التصيد الاحتيالي</li>
                </ul>
            </div>
        </div>
    </div>
    
    <script>
        function togglePassword() {
            const passwordInput = document.getElementById('password');
            const type = passwordInput.type === 'password' ? 'text' : 'password';
            passwordInput.type = type;
        }
        
        // منع إعادة تعبئة النموذج عند تحديث الصفحة
        if (window.history.replaceState) {
            window.history.replaceState(null, null, window.location.href);
        }
        
        // إخفاء رسائل الخطأ بعد 5 ثواني
        setTimeout(() => {
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {
                alert.style.opacity = '0';
                setTimeout(() => alert.remove(), 500);
            });
        }, 5000);
    </script>
</body>
</html>