<?php
session_start();
require_once 'includes/Auth.php';

$auth = new Auth();
$error = '';
$success = '';
$token = $_GET['token'] ?? '';

if (!$token) {
    $error = 'رابط إعادة التعيين غير صالح';
} else {
    // التحقق من صلاحية التوكن (بدون استخدامه)
    $pdo = Database::getInstance();
    $stmt = $pdo->prepare("SELECT * FROM password_resets WHERE reset_token = ? AND expires_at > NOW() AND used_at IS NULL");
    $stmt->execute([$token]);
    $resetRequest = $stmt->fetch();
    
    if (!$resetRequest) {
        $error = 'رابط إعادة التعيين غير صالح أو منتهي الصلاحية';
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $token) {
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];
    
    if ($password !== $confirm_password) {
        $error = 'كلمات المرور غير متطابقة';
    } else {
        $result = $auth->resetPassword($token, $password);
        
        if ($result['success']) {
            $success = $result['message'];
            $token = ''; // إخفاء النموذج بعد النجاح
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
    <title>تعيين كلمة مرور جديدة</title>
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
        
        .reset-container {
            width: 100%;
            max-width: 400px;
        }
        
        .reset-card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }
        
        .reset-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .reset-header h2 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .reset-header p {
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
            .reset-card {
                padding: 30px 20px;
            }
        }
    </style>
</head>
<body>
    <div class="reset-container">
        <div class="reset-card">
            <div class="reset-header">
                <h2>تعيين كلمة مرور جديدة</h2>
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
                    <p style="margin-top: 10px;"><a href="login.php">سجل الدخول الآن</a></p>
                </div>
            <?php endif; ?>
            
            <?php if (!$success && $token): ?>
            <form method="POST" action="">
                <div class="form-group">
                    <label for="password">كلمة المرور الجديدة</label>
                    <input type="password" id="password" name="password" required 
                           minlength="8" placeholder="********" dir="ltr">
                </div>
                
                <div class="form-group">
                    <label for="confirm_password">تأكيد كلمة المرور الجديدة</label>
                    <input type="password" id="confirm_password" name="confirm_password" required 
                           minlength="8" placeholder="********" dir="ltr">
                </div>
                
                <button type="submit" class="btn btn-primary">
                    تعيين كلمة المرور
                </button>
            </form>
            <?php endif; ?>
            
            <div class="auth-links">
                <a href="login.php">العودة لتسجيل الدخول</a>
                <span>•</span>
                <a href="index.php">الرئيسية</a>
            </div>
        </div>
    </div>
</body>
</html>