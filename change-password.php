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

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $current_password = $_POST['current_password'];
    $new_password = $_POST['new_password'];
    $confirm_password = $_POST['confirm_password'];
    
    if ($new_password !== $confirm_password) {
        $error = 'كلمات المرور الجديدة غير متطابقة';
    } else {
        // التحقق من كلمة المرور الحالية
        if (!password_verify($current_password, $user['password_hash'])) {
            $error = 'كلمة المرور الحالية غير صحيحة';
        } else {
            // التحقق من قوة كلمة المرور الجديدة
            $passwordStrength = $auth->checkPasswordStrength($new_password, $user['role']);
            if (!$passwordStrength['valid']) {
                $error = $passwordStrength['message'];
            } else {
                // تحديث كلمة المرور
                $hashedPassword = password_hash($new_password, PASSWORD_BCRYPT, ['cost' => 12]);
                
                $pdo = Database::getInstance();
                $stmt = $pdo->prepare("UPDATE users SET password_hash = ?, last_password_change = NOW() WHERE id = ?");
                $stmt->execute([$hashedPassword, $user['id']]);
                
                // تسجيل الحدث
                $auth->logSecurityEvent($user['id'], 'PASSWORD_CHANGED', 'تم تغيير كلمة المرور');
                
                $success = 'تم تغيير كلمة المرور بنجاح';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تغيير كلمة المرور</title>
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
            min-height: 100vh;
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
        
        .user-menu a {
            color: white;
            text-decoration: none;
            margin-right: 20px;
        }
        
        .user-menu a:hover {
            text-decoration: underline;
        }
        
        .container {
            max-width: 600px;
            margin: 40px auto;
            padding: 0 20px;
        }
        
        .card {
            background: white;
            border-radius: 15px;
            padding: 40px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
        }
        
        .card-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .card-header h2 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .card-header p {
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
        
        .password-strength {
            margin-top: 10px;
            padding: 10px;
            border-radius: 5px;
            font-size: 14px;
        }
        
        .strength-weak {
            background: #ffcdd2;
            color: #c62828;
            border-right: 4px solid #c62828;
        }
        
        .strength-medium {
            background: #fff3e0;
            color: #ef6c00;
            border-right: 4px solid #ef6c00;
        }
        
        .strength-strong {
            background: #e8f5e9;
            color: #2e7d32;
            border-right: 4px solid #2e7d32;
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
        
        @media (max-width: 480px) {
            .container {
                padding: 0 10px;
            }
            
            .card {
                padding: 20px;
            }
            
            .navbar {
                flex-direction: column;
                gap: 15px;
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="navbar-brand">
            تغيير كلمة المرور
        </div>
        <div class="user-menu">
            <a href="dashboard.php">العودة للوحة التحكم</a>
            <a href="logout.php">تسجيل الخروج</a>
        </div>
    </nav>
    
    <div class="container">
        <div class="card">
            <div class="card-header">
                <h2>تغيير كلمة المرور</h2>
                <p>اختر كلمة مرور قوية لحسابك</p>
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
            
            <form method="POST" action="" id="passwordForm">
                <div class="form-group">
                    <label for="current_password">كلمة المرور الحالية</label>
                    <input type="password" id="current_password" name="current_password" required 
                           placeholder="********" dir="ltr">
                </div>
                
                <div class="form-group">
                    <label for="new_password">كلمة المرور الجديدة</label>
                    <input type="password" id="new_password" name="new_password" required 
                           minlength="8" placeholder="********" dir="ltr"
                           oninput="checkPasswordStrength()">
                    <div id="passwordStrength" class="password-strength" style="display: none;"></div>
                </div>
                
                <div class="form-group">
                    <label for="confirm_password">تأكيد كلمة المرور الجديدة</label>
                    <input type="password" id="confirm_password" name="confirm_password" required 
                           minlength="8" placeholder="********" dir="ltr"
                           oninput="checkPasswordMatch()">
                    <div id="passwordMatch" style="margin-top: 5px; font-size: 14px;"></div>
                </div>
                
                <button type="submit" class="btn btn-primary" id="submitBtn">
                    تغيير كلمة المرور
                </button>
            </form>
            
            <div class="auth-links">
                <a href="dashboard.php">العودة للوحة التحكم</a>
                <span>•</span>
                <a href="index.php">الرئيسية</a>
            </div>
        </div>
    </div>
    
    <script>
        function checkPasswordStrength() {
            const password = document.getElementById('new_password').value;
            const strengthDiv = document.getElementById('passwordStrength');
            const submitBtn = document.getElementById('submitBtn');
            
            if (password.length === 0) {
                strengthDiv.style.display = 'none';
                return;
            }
            
            strengthDiv.style.display = 'block';
            
            const hasLength = password.length >= 8;
            const hasUpper = /[A-Z]/.test(password);
            const hasLower = /[a-z]/.test(password);
            const hasNumber = /[0-9]/.test(password);
            
            let strength = 0;
            if (hasLength) strength++;
            if (hasUpper) strength++;
            if (hasLower) strength++;
            if (hasNumber) strength++;
            
            if (strength < 2) {
                strengthDiv.className = 'password-strength strength-weak';
                strengthDiv.innerHTML = 'كلمة المرور ضعيفة';
                submitBtn.disabled = true;
            } else if (strength < 4) {
                strengthDiv.className = 'password-strength strength-medium';
                strengthDiv.innerHTML = 'كلمة المرور متوسطة';
                submitBtn.disabled = false;
            } else {
                strengthDiv.className = 'password-strength strength-strong';
                strengthDiv.innerHTML = 'كلمة المرور قوية';
                submitBtn.disabled = false;
            }
        }
        
        function checkPasswordMatch() {
            const password = document.getElementById('new_password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            const matchDiv = document.getElementById('passwordMatch');
            const submitBtn = document.getElementById('submitBtn');
            
            if (confirmPassword.length === 0) {
                matchDiv.innerHTML = '';
                return;
            }
            
            if (password === confirmPassword) {
                matchDiv.innerHTML = '<span style="color: #2e7d32;">✓ كلمات المرور متطابقة</span>';
                submitBtn.disabled = false;
            } else {
                matchDiv.innerHTML = '<span style="color: #c62828;">✗ كلمات المرور غير متطابقة</span>';
                submitBtn.disabled = true;
            }
        }
        
        document.addEventListener('DOMContentLoaded', function() {
            const password = document.getElementById('new_password').value;
            if (password) {
                checkPasswordStrength();
            }
            
            const confirmPassword = document.getElementById('confirm_password').value;
            if (confirmPassword) {
                checkPasswordMatch();
            }
        });
    </script>
</body>
</html>