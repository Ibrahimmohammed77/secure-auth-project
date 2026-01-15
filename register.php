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
    $data = [
        'email' => filter_var($_POST['email'], FILTER_SANITIZE_EMAIL),
        'password' => $_POST['password'],
        'confirm_password' => $_POST['confirm_password'],
        'username' => $_POST['username'] ?? null,
        'role' => $_POST['role'] ?? 'student'
    ];
    
    // التحقق من تطابق كلمات المرور
    if ($data['password'] !== $data['confirm_password']) {
        $error = 'كلمات المرور غير متطابقة';
    } else {
        $result = $auth->register($data);
        
        if ($result['success']) {
            $success = 'تم إنشاء الحساب بنجاح! يمكنك الآن تسجيل الدخول.';
            // مسح البيانات
            $_POST = [];
        } else {
            $error = $result['message'];
        }
    }
}
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>إنشاء حساب - نظام التعليم الإلكتروني</title>
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
        
        .register-container {
            width: 100%;
            max-width: 500px;
        }
        
        .register-card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }
        
        .register-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .register-header h2 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .register-header p {
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
        
        .form-group input,
        .form-group select {
            width: 100%;
            padding: 15px;
            border: 2px solid #ddd;
            border-radius: 10px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus,
        .form-group select:focus {
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
        
        .password-requirements {
            margin-top: 10px;
            padding-right: 20px;
        }
        
        .password-requirements li {
            margin-bottom: 5px;
            font-size: 14px;
            color: #666;
            list-style: none;
            position: relative;
        }
        
        .password-requirements li:before {
            content: '○';
            position: absolute;
            right: -15px;
        }
        
        .password-requirements li.valid:before {
            content: '✓';
            color: #2e7d32;
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
            .register-card {
                padding: 30px 20px;
            }
        }
    </style>
</head>
<body>
    <div class="register-container">
        <div class="register-card">
            <div class="register-header">
                <h2>إنشاء حساب جديد</h2>
                <p>انضم إلى منصتنا التعليمية الآمنة</p>
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
            
            <form method="POST" action="" id="registerForm">
                <div class="form-group">
                    <label for="email">البريد الإلكتروني *</label>
                    <input type="email" id="email" name="email" required 
                           placeholder="example@domain.com" dir="ltr"
                           value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>">
                </div>
                
                <div class="form-group">
                    <label for="username">اسم المستخدم (اختياري)</label>
                    <input type="text" id="username" name="username" 
                           placeholder="الاسم الذي سيظهر في المنصة"
                           value="<?php echo isset($_POST['username']) ? htmlspecialchars($_POST['username']) : ''; ?>">
                </div>
                
                <div class="form-group">
                    <label for="role">نوع الحساب *</label>
                    <select id="role" name="role" required>
                        <option value="student" <?php echo (isset($_POST['role']) && $_POST['role'] === 'student') ? 'selected' : ''; ?>>طالب</option>
                        <option value="teacher" <?php echo (isset($_POST['role']) && $_POST['role'] === 'teacher') ? 'selected' : ''; ?>>مدرس</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label for="password">كلمة المرور *</label>
                    <input type="password" id="password" name="password" required 
                           minlength="8" placeholder="********" dir="ltr"
                           oninput="checkPasswordStrength()">
                    <div id="passwordStrength" class="password-strength" style="display: none;"></div>
                    
                    <ul class="password-requirements" id="passwordRequirements">
                        <li id="reqLength">8 أحرف على الأقل</li>
                        <li id="reqUpper">حرف كبير واحد على الأقل</li>
                        <li id="reqLower">حرف صغير واحد على الأقل</li>
                        <li id="reqNumber">رقم واحد على الأقل</li>
                    </ul>
                </div>
                
                <div class="form-group">
                    <label for="confirm_password">تأكيد كلمة المرور *</label>
                    <input type="password" id="confirm_password" name="confirm_password" required 
                           minlength="8" placeholder="********" dir="ltr"
                           oninput="checkPasswordMatch()">
                    <div id="passwordMatch" style="margin-top: 5px; font-size: 14px;"></div>
                </div>
                
                <div class="form-group">
                    <div style="display: flex; align-items: center; margin-bottom: 10px;">
                        <input type="checkbox" id="terms" name="terms" required style="width: auto; margin-left: 10px;">
                        <label for="terms" style="margin: 0;">
                            أوافق على <a href="terms.php" style="color: #667eea;">الشروط والأحكام</a> و
                            <a href="privacy.php" style="color: #667eea;">سياسة الخصوصية</a>
                        </label>
                    </div>
                </div>
                
                <button type="submit" class="btn btn-primary" id="submitBtn">
                    إنشاء الحساب
                </button>
            </form>
            
            <div class="auth-links">
                <a href="login.php">لديك حساب؟ سجل الدخول</a>
                <span>•</span>
                <a href="index.php">الرئيسية</a>
            </div>
        </div>
    </div>
    
    <script>
        function checkPasswordStrength() {
            const password = document.getElementById('password').value;
            const strengthDiv = document.getElementById('passwordStrength');
            const submitBtn = document.getElementById('submitBtn');
            
            // إخفاء إذا لم يكن هناك نص
            if (password.length === 0) {
                strengthDiv.style.display = 'none';
                resetRequirements();
                return;
            }
            
            strengthDiv.style.display = 'block';
            
            // التحقق من المتطلبات
            const hasLength = password.length >= 8;
            const hasUpper = /[A-Z]/.test(password);
            const hasLower = /[a-z]/.test(password);
            const hasNumber = /[0-9]/.test(password);
            
            // تحديث علامات المتطلبات
            updateRequirement('reqLength', hasLength);
            updateRequirement('reqUpper', hasUpper);
            updateRequirement('reqLower', hasLower);
            updateRequirement('reqNumber', hasNumber);
            
            // حساب القوة
            let strength = 0;
            if (hasLength) strength++;
            if (hasUpper) strength++;
            if (hasLower) strength++;
            if (hasNumber) strength++;
            
            // عرض القوة
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
        
        function updateRequirement(elementId, isValid) {
            const element = document.getElementById(elementId);
            if (isValid) {
                element.classList.add('valid');
            } else {
                element.classList.remove('valid');
            }
        }
        
        function resetRequirements() {
            const requirements = document.querySelectorAll('.password-requirements li');
            requirements.forEach(req => {
                req.classList.remove('valid');
            });
        }
        
        function checkPasswordMatch() {
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            const matchDiv = document.getElementById('passwordMatch');
            
            if (confirmPassword.length === 0) {
                matchDiv.innerHTML = '';
                return;
            }
            
            if (password === confirmPassword) {
                matchDiv.innerHTML = '<span style="color: #2e7d32;">✓ كلمات المرور متطابقة</span>';
            } else {
                matchDiv.innerHTML = '<span style="color: #c62828;">✗ كلمات المرور غير متطابقة</span>';
            }
        }
        
        // التحقق من القوة عند تحميل الصفحة
        document.addEventListener('DOMContentLoaded', function() {
            const password = document.getElementById('password').value;
            if (password) {
                checkPasswordStrength();
            }
            
            const confirmPassword = document.getElementById('confirm_password').value;
            if (confirmPassword) {
                checkPasswordMatch();
            }
        });
        
        // منع إعادة تعبئة النموذج عند تحديث الصفحة
        if (window.history.replaceState) {
            window.history.replaceState(null, null, window.location.href);
        }
    </script>
</body>
</html>