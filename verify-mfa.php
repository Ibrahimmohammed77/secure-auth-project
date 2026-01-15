<?php
session_start();
require_once 'includes/Auth.php';

$auth = new Auth();
$error = '';

// التحقق من وجود محاولة تسجيل دخول معلقة
if (!isset($_SESSION['pending_login'])) {
    header('Location: login.php');
    exit;
}

$pendingLogin = $_SESSION['pending_login'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $mfaCode = $_POST['mfa_code'];
    
    // محاولة تسجيل الدخول مع رمز MFA
    $result = $auth->login($pendingLogin['email'], $pendingLogin['password'], $mfaCode);
    
    if ($result['success']) {
        // مسح بيانات تسجيل الدخول المعلقة
        unset($_SESSION['pending_login']);
        
        // تسجيل الدخول الناجح
        $_SESSION['user'] = $result['user'];
        header('Location: dashboard.php');
        exit;
    } else {
        $error = $result['message'];
        
        // إذا فشلت MFA عدة مرات، ألغِ محاولة تسجيل الدخول
        if (!isset($_SESSION['mfa_attempts'])) {
            $_SESSION['mfa_attempts'] = 1;
        } else {
            $_SESSION['mfa_attempts']++;
        }
        
        if ($_SESSION['mfa_attempts'] >= 3) {
            unset($_SESSION['pending_login']);
            unset($_SESSION['mfa_attempts']);
            header('Location: login.php?error=mfa_failed');
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
    <title>التحقق الثنائي</title>
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
        
        .verify-container {
            width: 100%;
            max-width: 400px;
        }
        
        .verify-card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }
        
        .verify-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .verify-header h2 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .verify-header p {
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
        
        .mfa-instructions {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .mfa-instructions p {
            margin-bottom: 10px;
            color: #555;
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
        
        .mfa-inputs {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-bottom: 20px;
        }
        
        .mfa-inputs input {
            width: 50px;
            height: 60px;
            text-align: center;
            font-size: 24px;
            border: 2px solid #ddd;
            border-radius: 10px;
            transition: all 0.3s;
        }
        
        .mfa-inputs input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.2);
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
        
        .btn-secondary {
            background: #f0f0f0;
            color: #333;
            margin-top: 10px;
        }
        
        .btn-secondary:hover {
            background: #e0e0e0;
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
            .verify-card {
                padding: 30px 20px;
            }
            
            .mfa-inputs input {
                width: 40px;
                height: 50px;
                font-size: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="verify-container">
        <div class="verify-card">
            <div class="verify-header">
                <h2>التحقق الثنائي</h2>
                <p>أدخل رمز التحقق من تطبيق المصادقة</p>
            </div>
            
            <?php if ($error): ?>
                <div class="alert alert-danger">
                    <?php echo htmlspecialchars($error); ?>
                    <?php if (isset($_SESSION['mfa_attempts'])): ?>
                        <br><small>المحاولة <?php echo $_SESSION['mfa_attempts']; ?> من 3</small>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
            
            <div class="mfa-instructions">
                <p>افتح تطبيق المصادقة على هاتفك</p>
                <p>أدخل رمز التحقق المكون من 6 أرقام</p>
            </div>
            
            <form method="POST" action="" id="mfaForm">
                <div class="form-group">
                    <label for="mfa_code">رمز التحقق</label>
                    <div class="mfa-inputs">
                        <?php for ($i = 1; $i <= 6; $i++): ?>
                            <input type="text" 
                                   maxlength="1" 
                                   pattern="[0-9]" 
                                   oninput="this.value = this.value.replace(/[^0-9]/g, ''); moveToNext(this, <?php echo $i; ?>);"
                                   onkeydown="handleBackspace(this, <?php echo $i; ?>, event)"
                                   id="digit<?php echo $i; ?>"
                                   name="digit<?php echo $i; ?>"
                                   autocomplete="off">
                        <?php endfor; ?>
                    </div>
                    <input type="hidden" name="mfa_code" id="mfa_code">
                </div>
                
                <button type="submit" class="btn btn-primary" id="submitBtn" disabled>
                    التحقق
                </button>
                
                <button type="button" class="btn btn-secondary" onclick="window.location.href='login.php'">
                    إلغاء والعودة لتسجيل الدخول
                </button>
            </form>
            
            <div class="auth-links">
                <a href="forgot-password.php">استعادة كلمة المرور</a>
                <span>•</span>
                <a href="index.php">الرئيسية</a>
            </div>
        </div>
    </div>
    
    <script>
        // دالة للانتقال للحقل التالي
        function moveToNext(input, currentIndex) {
            if (input.value.length === 1 && currentIndex < 6) {
                document.getElementById('digit' + (currentIndex + 1)).focus();
            }
            updateMFACode();
        }
        
        // دالة للتعامل مع مفتاح backspace
        function handleBackspace(input, currentIndex, event) {
            if (event.key === 'Backspace' && input.value === '' && currentIndex > 1) {
                document.getElementById('digit' + (currentIndex - 1)).focus();
            }
            updateMFACode();
        }
        
        // تحديث حقل MFA المخفي
        function updateMFACode() {
            let mfaCode = '';
            for (let i = 1; i <= 6; i++) {
                mfaCode += document.getElementById('digit' + i).value;
            }
            document.getElementById('mfa_code').value = mfaCode;
            
            // تفعيل زر الإرسال إذا كان الرمز كامل
            document.getElementById('submitBtn').disabled = mfaCode.length !== 6;
        }
        
        // التركيز على الحقل الأول عند تحميل الصفحة
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('digit1').focus();
            
            // إضافة مستمع للأحداث لجميع الحقول
            for (let i = 1; i <= 6; i++) {
                document.getElementById('digit' + i).addEventListener('paste', function(e) {
                    e.preventDefault();
                    const pastedText = e.clipboardData.getData('text');
                    const digits = pastedText.replace(/[^0-9]/g, '').substring(0, 6);
                    
                    for (let j = 0; j < digits.length; j++) {
                        if (j < 6) {
                            document.getElementById('digit' + (j + 1)).value = digits[j];
                        }
                    }
                    
                    if (digits.length === 6) {
                        document.getElementById('digit6').focus();
                    } else if (digits.length < 6 && digits.length > 0) {
                        document.getElementById('digit' + (digits.length)).focus();
                    }
                    
                    updateMFACode();
                });
            }
        });
        
        // منع إعادة تعبئة النموذج عند تحديث الصفحة
        if (window.history.replaceState) {
            window.history.replaceState(null, null, window.location.href);
        }
    </script>
</body>
</html>