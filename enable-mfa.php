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

// إذا كان MFA مفعل بالفعل
if ($user['mfa_enabled']) {
    header('Location: dashboard.php');
    exit;
}

$error = '';
$success = '';
$secret = '';
$qrCodeUrl = '';

// توليد السر السري لـ MFA
if (!isset($_SESSION['mfa_secret'])) {
    // في بيئة حقيقية، استخدم مكتبة مثل robthree/twofactorauth
    // هنا نولد سر عشوائي (32 حرف قاعدة32)
    $secret = rtrim(strtr(base64_encode(random_bytes(20)), '+/', '-_'), '=');
    $_SESSION['mfa_secret'] = $secret;
} else {
    $secret = $_SESSION['mfa_secret'];
}

// إنشاء رابط QR Code (شكلي - في الإنتاج استخدم مكتبة)
$qrCodeUrl = "https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=" . urlencode("otpauth://totp/نظام التعليم:{$user['email']}?secret={$secret}&issuer=نظام التعليم");

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $code = $_POST['code'];
    
    // التحقق من الكود (في الإنتاج استخدم مكتبة)
    // هنا نتحقق فقط من أن الكود 6 أرقام
    if (strlen($code) === 6 && is_numeric($code)) {
        // حفظ السر في قاعدة البيانات
        $pdo = Database::getInstance();
        
        // إنشاء رموز احتياطية
        $backupCodes = [];
        for ($i = 0; $i < 10; $i++) {
            $backupCodes[] = bin2hex(random_bytes(4));
        }
        
        $stmt = $pdo->prepare("UPDATE users SET mfa_secret = ?, mfa_enabled = TRUE, mfa_backup_codes = ? WHERE id = ?");
        $stmt->execute([$secret, json_encode($backupCodes), $user['id']]);
        
        // تسجيل الحدث
        $auth->logSecurityEvent($user['id'], 'MFA_ENABLED', 'تم تفعيل المصادقة الثنائية');
        
        // مسح السر من الجلسة
        unset($_SESSION['mfa_secret']);
        
        $success = 'تم تفعيل المصادقة الثنائية بنجاح!';
        
        // عرض الرموز الاحتياطية (في بيئة حقيقية، يجب حفظها بأمان)
        $_SESSION['backup_codes'] = $backupCodes;
        
    } else {
        $error = 'رمز التحقق غير صحيح. الرجاء المحاولة مرة أخرى.';
    }
}
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تفعيل المصادقة الثنائية</title>
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
        
        .mfa-container {
            width: 100%;
            max-width: 500px;
        }
        
        .mfa-card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }
        
        .mfa-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .mfa-header h2 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .mfa-header p {
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
        
        .setup-steps {
            margin-bottom: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
        }
        
        .setup-steps ol {
            padding-right: 20px;
        }
        
        .setup-steps li {
            margin-bottom: 10px;
            color: #555;
        }
        
        .qr-section {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .qr-code {
            display: inline-block;
            padding: 20px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }
        
        .qr-code img {
            max-width: 200px;
            height: auto;
        }
        
        .manual-secret {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
            font-family: monospace;
            font-size: 18px;
            letter-spacing: 2px;
            word-break: break-all;
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
            text-align: center;
            letter-spacing: 5px;
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
        
        .backup-codes {
            margin-top: 20px;
            padding: 20px;
            background: #fff3cd;
            border-radius: 10px;
            border-right: 4px solid #ffc107;
        }
        
        .backup-codes h4 {
            color: #856404;
            margin-bottom: 10px;
        }
        
        .backup-codes ul {
            columns: 2;
            -webkit-columns: 2;
            -moz-columns: 2;
            list-style: none;
            padding: 0;
        }
        
        .backup-codes li {
            padding: 5px;
            font-family: monospace;
            font-size: 14px;
            margin-bottom: 5px;
            background: white;
            border-radius: 5px;
            text-align: center;
        }
        
        @media (max-width: 480px) {
            .mfa-card {
                padding: 30px 20px;
            }
            
            .backup-codes ul {
                columns: 1;
                -webkit-columns: 1;
                -moz-columns: 1;
            }
        }
    </style>
</head>
<body>
    <div class="mfa-container">
        <div class="mfa-card">
            <div class="mfa-header">
                <h2>تفعيل المصادقة الثنائية</h2>
                <p>حسابك أكثر أمانًا مع خطوة تحقق إضافية</p>
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
                
                <?php if (isset($_SESSION['backup_codes'])): ?>
                <div class="backup-codes">
                    <h4>⚠️ احفظ هذه الرموز الاحتياطية في مكان آمن</h4>
                    <p>ستحتاجها إذا فقدت هاتفك:</p>
                    <ul>
                        <?php foreach ($_SESSION['backup_codes'] as $code): ?>
                            <li><?php echo htmlspecialchars($code); ?></li>
                        <?php endforeach; ?>
                    </ul>
                    <p style="margin-top: 10px; font-size: 14px; color: #856404;">
                        <strong>ملاحظة:</strong> هذه الرموز لن تظهر مرة أخرى.
                    </p>
                </div>
                <?php 
                    unset($_SESSION['backup_codes']);
                endif; ?>
                
                <div style="text-align: center; margin-top: 20px;">
                    <a href="dashboard.php" class="btn btn-primary">العودة للوحة التحكم</a>
                </div>
                
            <?php else: ?>
            
            <div class="setup-steps">
                <h3>خطوات التفعيل:</h3>
                <ol>
                    <li>ثبت تطبيق المصادقة على هاتفك (Google Authenticator أو Microsoft Authenticator)</li>
                    <li>امسح QR Code بالكاميرا أو أدخل الرمز السري يدويًا</li>
                    <li>أدخل رمز التحقق المكون من 6 أرقام</li>
                </ol>
            </div>
            
            <div class="qr-section">
                <div class="qr-code">
                    <img src="<?php echo htmlspecialchars($qrCodeUrl); ?>" alt="QR Code">
                </div>
                <p>أو أدخل الرمز السري يدويًا:</p>
                <div class="manual-secret">
                    <?php echo chunk_split($secret, 4, ' '); ?>
                </div>
            </div>
            
            <form method="POST" action="">
                <div class="form-group">
                    <label for="code">رمز التحقق المكون من 6 أرقام</label>
                    <input type="text" id="code" name="code" required 
                           pattern="[0-9]{6}" maxlength="6" minlength="6"
                           placeholder="123456" dir="ltr"
                           oninput="this.value = this.value.replace(/[^0-9]/g, '')">
                </div>
                
                <button type="submit" class="btn btn-primary">
                    تفعيل المصادقة الثنائية
                </button>
                
                <button type="button" class="btn btn-secondary" onclick="window.location.href='dashboard.php'">
                    تخطي الآن
                </button>
            </form>
            
            <?php endif; ?>
            
            <div class="auth-links">
                <a href="dashboard.php">العودة للوحة التحكم</a>
                <span>•</span>
                <a href="index.php">الرئيسية</a>
            </div>
        </div>
    </div>
</body>
</html>