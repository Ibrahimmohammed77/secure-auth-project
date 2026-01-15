<?php
require_once __DIR__ . '/Database.php';

class Auth {
    private $db;
    private $config;
    
    public function __construct() {
        $this->db = Database::getInstance();
        $this->config = require __DIR__ . '/../config/config.php';
    }
    
    /**
     * تسجيل مستخدم جديد
     */
    public function register($data) {
        // التحقق من البيانات الأساسية
        if (empty($data['email']) || empty($data['password'])) {
            return ['success' => false, 'message' => 'البريد الإلكتروني وكلمة المرور مطلوبان'];
        }
        
        // التحقق من صحة البريد الإلكتروني
        if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            return ['success' => false, 'message' => 'البريد الإلكتروني غير صالح'];
        }
        
        // التحقق من قوة كلمة المرور
        $passwordStrength = $this->checkPasswordStrength($data['password'], $data['role'] ?? 'student');
        if (!$passwordStrength['valid']) {
            return ['success' => false, 'message' => $passwordStrength['message']];
        }
        
        // التحقق من عدم وجود المستخدم مسبقًا
        if ($this->userExists($data['email'])) {
            return ['success' => false, 'message' => 'البريد الإلكتروني مسجل مسبقًا'];
        }
        
        try {
            // تجهيز البيانات
            $uuid = $this->generateUUID();
            $hashedPassword = password_hash($data['password'], PASSWORD_BCRYPT, [
                'cost' => $this->config['security']['bcrypt_cost']
            ]);
            
            // إدخال المستخدم في قاعدة البيانات
            $stmt = $this->db->prepare("
                INSERT INTO users (uuid, email, username, password_hash, role) 
                VALUES (:uuid, :email, :username, :password_hash, :role)
            ");
            
            $stmt->execute([
                ':uuid' => $uuid,
                ':email' => $data['email'],
                ':username' => $data['username'] ?? null,
                ':password_hash' => $hashedPassword,
                ':role' => $data['role'] ?? 'student'
            ]);
            
            $userId = $this->db->lastInsertId();
            
            // تسجيل الحدث
            $this->logSecurityEvent($userId, 'REGISTRATION', 'تم تسجيل مستخدم جديد');
            
            return [
                'success' => true,
                'message' => 'تم إنشاء الحساب بنجاح',
                'user_id' => $userId,
                'uuid' => $uuid
            ];
            
        } catch (PDOException $e) {
            error_log("فشل التسجيل: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'حدث خطأ تقني. الرجاء المحاولة لاحقًا.'
            ];
        }
    }
    
    /**
     * تسجيل الدخول الآمن
     */
    public function login($email, $password, $mfaCode = null) {
        // التحقق من معدل المحاولات
        if ($this->isIpRateLimited()) {
            return [
                'success' => false,
                'message' => 'تم تجاوز عدد المحاولات المسموح بها. الرجاء الانتظار 15 دقيقة.'
            ];
        }
        
        // تسجيل محاولة الدخول
        $attemptId = $this->logLoginAttempt($email);
        
        // البحث عن المستخدم
        $user = $this->getUserByEmail($email);
        
        if (!$user) {
            $this->updateLoginAttempt($attemptId, 'wrong_password');
            $this->delayResponse(); // إضافة تأخير
            return $this->genericErrorResponse();
        }
        
        // التحقق من حالة الحساب
        if (!$user['is_active']) {
            $this->updateLoginAttempt($attemptId, 'account_locked');
            return [
                'success' => false,
                'message' => 'الحساب غير مفعل'
            ];
        }
        
        // التحقق من قفل الحساب
        if ($user['account_locked_until'] && strtotime($user['account_locked_until']) > time()) {
            $this->updateLoginAttempt($attemptId, 'account_locked');
            return [
                'success' => false,
                'message' => 'الحساب مقفل مؤقتًا بسبب محاولات دخول فاشلة متعددة'
            ];
        }
        
        // التحقق من كلمة المرور
        if (!password_verify($password, $user['password_hash'])) {
            $this->incrementFailedAttempts($user['id']);
            $this->updateLoginAttempt($attemptId, 'wrong_password');
            $this->delayResponse();
            return $this->genericErrorResponse();
        }
        
        // التحقق من MFA إذا مفعل
        if ($user['mfa_enabled'] && $user['mfa_secret']) {
            if (!$mfaCode) {
                $this->updateLoginAttempt($attemptId, 'mfa_failed');
                return [
                    'success' => false,
                    'message' => 'مطلوب رمز التحقق الثنائي',
                    'requires_mfa' => true
                ];
            }
            
            if (!$this->verifyMFA($user['mfa_secret'], $mfaCode)) {
                // التحقق من الرموز الاحتياطية
                if (!$this->verifyBackupCode($user['id'], $mfaCode)) {
                    $this->updateLoginAttempt($attemptId, 'mfa_failed');
                    return [
                        'success' => false,
                        'message' => 'رمز التحقق الثنائي غير صحيح'
                    ];
                }
            }
        }
        
        // النجاح - تحديث معلومات المستخدم
        $this->resetFailedAttempts($user['id']);
        $this->updateLastLogin($user['id']);
        $this->updateLoginAttempt($attemptId, 'success');
        
        // إنشاء جلسة آمنة
        $session = $this->createSecureSession($user);
        
        // تسجيل الحدث
        $this->logSecurityEvent($user['id'], 'LOGIN_SUCCESS', 'تم تسجيل الدخول بنجاح');
        
        return [
            'success' => true,
            'message' => 'تم تسجيل الدخول بنجاح',
            'session_token' => $session['token'],
            'user' => [
                'id' => $user['id'],
                'uuid' => $user['uuid'],
                'email' => $user['email'],
                'role' => $user['role'],
                'mfa_enabled' => $user['mfa_enabled']
            ]
        ];
    }
    
    /**
     * إنشاء جلسة آمنة
     */
    private function createSecureSession($user) {
        $token = bin2hex(random_bytes(32));
        $deviceFingerprint = $this->generateDeviceFingerprint();
        
        $stmt = $this->db->prepare("
            INSERT INTO user_sessions 
            (user_id, session_token, ip_address, user_agent, device_fingerprint, expires_at) 
            VALUES (:user_id, :token, :ip, :ua, :device, DATE_ADD(NOW(), INTERVAL 24 HOUR))
        ");
        
        $stmt->execute([
            ':user_id' => $user['id'],
            ':token' => $token,
            ':ip' => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
            ':ua' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            ':device' => $deviceFingerprint
        ]);
        
        // إعداد الكوكيز الآمنة
        setcookie(
            'session_token',
            $token,
            [
                'expires' => time() + $this->config['session']['cookie_lifetime'],
                'path' => '/',
                'domain' => '',
                'secure' => $this->config['session']['cookie_secure'],
                'httponly' => $this->config['session']['cookie_httponly'],
                'samesite' => $this->config['session']['cookie_samesite']
            ]
        );
        
        return ['token' => $token];
    }
    
    /**
     * التحقق من صحة الجلسة
     */
    public function validateSession($token) {
        $stmt = $this->db->prepare("
            SELECT us.*, u.* 
            FROM user_sessions us
            JOIN users u ON us.user_id = u.id
            WHERE us.session_token = :token 
            AND us.expires_at > NOW() 
            AND us.is_revoked = FALSE
            AND u.is_active = TRUE
        ");
        
        $stmt->execute([':token' => $token]);
        $session = $stmt->fetch();
        
        if (!$session) {
            return false;
        }
        
        // التحقق من بصمة الجهاز
        $currentFingerprint = $this->generateDeviceFingerprint();
        if ($session['device_fingerprint'] !== $currentFingerprint) {
            $this->revokeSession($token);
            return false;
        }
        
        return $session;
    }
    
    /**
     * تسجيل خروج آمن
     */
    public function logout($token) {
        $session = $this->validateSession($token);
        
        if ($session) {
            $this->revokeSession($token);
            $this->logSecurityEvent($session['user_id'], 'LOGOUT', 'تم تسجيل الخروج');
        }
        
        // حذف الكوكي
        setcookie('session_token', '', time() - 3600, '/');
        
        return true;
    }
    
    /**
     * طلب إعادة تعيين كلمة المرور
     */
    public function requestPasswordReset($email) {
        $user = $this->getUserByEmail($email);
        
        if (!$user) {
            // إرجاع نفس الرسالة لأسباب أمنية
            return ['success' => true, 'message' => 'إذا كان البريد مسجلًا، ستتلقى رابط الإعادة'];
        }
        
        // التحقق من عدد الطلبات السابقة
        $stmt = $this->db->prepare("
            SELECT COUNT(*) as count 
            FROM password_resets 
            WHERE user_id = :user_id 
            AND requested_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
            AND used_at IS NULL
        ");
        
        $stmt->execute([':user_id' => $user['id']]);
        $result = $stmt->fetch();
        
        if ($result['count'] >= 3) {
            return [
                'success' => false,
                'message' => 'لقد طلبت إعادة التعيين عدة مرات. الرجاء الانتظار ساعة.'
            ];
        }
        
        // إنشاء توكن آمن
        $token = bin2hex(random_bytes(32));
        
        $stmt = $this->db->prepare("
            INSERT INTO password_resets 
            (user_id, reset_token, expires_at, ip_address) 
            VALUES (:user_id, :token, DATE_ADD(NOW(), INTERVAL 1 HOUR), :ip)
        ");
        
        $stmt->execute([
            ':user_id' => $user['id'],
            ':token' => $token,
            ':ip' => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'
        ]);
        
        // في بيئة حقيقية، أرسل البريد الإلكتروني هنا
        $resetLink = $this->config['app']['url'] . "/reset-password.php?token=" . $token;
        
        // تسجيل الحدث
        $this->logSecurityEvent($user['id'], 'PASSWORD_RESET_REQUEST', 'طلب إعادة تعيين كلمة المرور');
        
        // لأغراض العرض، سنرجع الرابط
        return [
            'success' => true,
            'message' => 'تم إنشاء رابط إعادة التعيين',
            'reset_link' => $resetLink // في الإنتاج لا ترجع الرابط!
        ];
    }
    
    /**
     * إعادة تعيين كلمة المرور
     */
    public function resetPassword($token, $newPassword) {
        // البحث عن طلب الإعادة
        $stmt = $this->db->prepare("
            SELECT pr.*, u.* 
            FROM password_resets pr
            JOIN users u ON pr.user_id = u.id
            WHERE pr.reset_token = :token 
            AND pr.expires_at > NOW() 
            AND pr.used_at IS NULL
        ");
        
        $stmt->execute([':token' => $token]);
        $resetRequest = $stmt->fetch();
        
        if (!$resetRequest) {
            return ['success' => false, 'message' => 'رابط إعادة التعيين غير صالح أو منتهي الصلاحية'];
        }
        
        // التحقق من قوة كلمة المرور الجديدة
        $passwordStrength = $this->checkPasswordStrength($newPassword, $resetRequest['role']);
        if (!$passwordStrength['valid']) {
            return ['success' => false, 'message' => $passwordStrength['message']];
        }
        
        // تحديث كلمة المرور
        $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT, [
            'cost' => $this->config['security']['bcrypt_cost']
        ]);
        
        try {
            $this->db->beginTransaction();
            
            // تحديث كلمة المرور
            $stmt = $this->db->prepare("
                UPDATE users 
                SET password_hash = :password_hash, 
                    last_password_change = NOW(),
                    failed_login_attempts = 0,
                    account_locked_until = NULL
                WHERE id = :user_id
            ");
            
            $stmt->execute([
                ':password_hash' => $hashedPassword,
                ':user_id' => $resetRequest['user_id']
            ]);
            
            // تعليم التوكن كمستخدم
            $stmt = $this->db->prepare("
                UPDATE password_resets 
                SET used_at = NOW() 
                WHERE id = :id
            ");
            
            $stmt->execute([':id' => $resetRequest['id']]);
            
            // إبطال جميع جلسات المستخدم
            $stmt = $this->db->prepare("
                UPDATE user_sessions 
                SET is_revoked = TRUE 
                WHERE user_id = :user_id
            ");
            
            $stmt->execute([':user_id' => $resetRequest['user_id']]);
            
            $this->db->commit();
            
            // تسجيل الحدث
            $this->logSecurityEvent($resetRequest['user_id'], 'PASSWORD_RESET', 'تم إعادة تعيين كلمة المرور');
            
            return [
                'success' => true,
                'message' => 'تم إعادة تعيين كلمة المرور بنجاح'
            ];
            
        } catch (PDOException $e) {
            $this->db->rollBack();
            error_log("فشل إعادة تعيين كلمة المرور: " . $e->getMessage());
            return ['success' => false, 'message' => 'حدث خطأ تقني'];
        }
    }
    
    // الدوال المساعدة
    private function getUserByEmail($email) {
        $stmt = $this->db->prepare("SELECT * FROM users WHERE email = :email");
        $stmt->execute([':email' => $email]);
        return $stmt->fetch();
    }
    
    private function userExists($email) {
        $stmt = $this->db->prepare("SELECT COUNT(*) as count FROM users WHERE email = :email");
        $stmt->execute([':email' => $email]);
        $result = $stmt->fetch();
        return $result['count'] > 0;
    }
    
    public function isIpRateLimited() {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $timeLimit = date('Y-m-d H:i:s', time() - 900); // 15 دقيقة
        
        $stmt = $this->db->prepare("
            SELECT COUNT(*) as count 
            FROM login_attempts 
            WHERE ip_address = :ip 
            AND attempted_at > :time_limit
            AND attempt_status = 'wrong_password'
        ");
        
        $stmt->execute([':ip' => $ip, ':time_limit' => $timeLimit]);
        $result = $stmt->fetch();
        
        return $result['count'] >= 10;
    }
    
    private function logLoginAttempt($email) {
        $stmt = $this->db->prepare("
            INSERT INTO login_attempts (email, ip_address, user_agent) 
            VALUES (:email, :ip, :ua)
        ");
        
        $stmt->execute([
            ':email' => $email,
            ':ip' => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
            ':ua' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        ]);
        
        return $this->db->lastInsertId();
    }
    
    private function updateLoginAttempt($id, $status) {
        $stmt = $this->db->prepare("
            UPDATE login_attempts 
            SET attempt_status = :status 
            WHERE id = :id
        ");
        
        $stmt->execute([':status' => $status, ':id' => $id]);
    }
    
    private function incrementFailedAttempts($userId) {
        $stmt = $this->db->prepare("
            UPDATE users 
            SET failed_login_attempts = failed_login_attempts + 1 
            WHERE id = :id
        ");
        
        $stmt->execute([':id' => $userId]);
        
        // قفل الحساب إذا تجاوز عدد المحاولات المسموح بها
        $stmt = $this->db->prepare("
            UPDATE users 
            SET account_locked_until = DATE_ADD(NOW(), INTERVAL 15 MINUTE) 
            WHERE id = :id 
            AND failed_login_attempts >= :max_attempts
        ");
        
        $stmt->execute([
            ':id' => $userId,
            ':max_attempts' => $this->config['security']['max_login_attempts']
        ]);
    }
    
    private function resetFailedAttempts($userId) {
        $stmt = $this->db->prepare("
            UPDATE users 
            SET failed_login_attempts = 0, 
                account_locked_until = NULL 
            WHERE id = :id
       ");
        
        $stmt->execute([':id' => $userId]);
    }
    
    private function updateLastLogin($userId) {
        $stmt = $this->db->prepare("
            UPDATE users 
            SET last_login_at = NOW() 
            WHERE id = :id
        ");
        
        $stmt->execute([':id' => $userId]);
    }
    
    private function revokeSession($token) {
        $stmt = $this->db->prepare("
            UPDATE user_sessions 
            SET is_revoked = TRUE 
            WHERE session_token = :token
        ");
        
        $stmt->execute([':token' => $token]);
    }
    
    private function generateUUID() {
        return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }
    
    private function generateDeviceFingerprint() {
        $components = [
            $_SERVER['HTTP_USER_AGENT'] ?? '',
            $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            $_SERVER['HTTP_ACCEPT_ENCODING'] ?? ''
        ];
        
        return hash('sha256', implode('|', $components));
    }
    
    private function delayResponse() {
        // إضافة تأخير عشوائي بين 1-3 ثواني
        usleep(rand(1000000, 3000000));
    }
    
    private function genericErrorResponse() {
        return [
            'success' => false,
            'message' => 'البريد الإلكتروني أو كلمة المرور غير صحيحة'
        ];
    }
    
    public function checkPasswordStrength($password, $role) {
        $minLength = $this->config['security']['min_password_length'];
        
        if (strlen($password) < $minLength) {
            return [
                'valid' => false,
                'message' => "كلمة المرور يجب أن تكون $minLength أحرف على الأقل"
            ];
        }
        
        // سياسات مختلفة حسب الدور
        if ($role === 'teacher' || $role === 'admin') {
            if (!preg_match('/[A-Z]/', $password) || 
                !preg_match('/[a-z]/', $password) || 
                !preg_match('/[0-9]/', $password)) {
                return [
                    'valid' => false,
                    'message' => 'كلمة المرور يجب أن تحتوي على حروف كبيرة وصغيرة وأرقام'
                ];
            }
        }
        
        // منع كلمات المرور الشائعة
        $commonPasswords = ['password', '123456', 'qwerty', 'password123', 'admin123'];
        if (in_array(strtolower($password), $commonPasswords)) {
            return [
                'valid' => false,
                'message' => 'كلمة المرور ضعيفة جدًا، الرجاء اختيار كلمة أقوى'
            ];
        }
        
        return ['valid' => true, 'message' => 'كلمة المرور قوية'];
    }
    
    private function verifyMFA($secret, $code) {
        // في بيئة حقيقية، استخدم مكتبة مثل robthree/twofactorauth
        // هذه نسخة مبسطة للعرض
        return strlen($code) === 6 && is_numeric($code);
    }
    
    private function verifyBackupCode($userId, $code) {
        $stmt = $this->db->prepare("SELECT mfa_backup_codes FROM users WHERE id = :id");
        $stmt->execute([':id' => $userId]);
        $user = $stmt->fetch();
        
        if (!$user['mfa_backup_codes']) {
            return false;
        }
        
        $backupCodes = json_decode($user['mfa_backup_codes'], true);
        
        if (in_array($code, $backupCodes)) {
            // حذف الرمز المستخدم
            $newCodes = array_diff($backupCodes, [$code]);
            $stmt = $this->db->prepare("UPDATE users SET mfa_backup_codes = :codes WHERE id = :id");
            $stmt->execute([':codes' => json_encode(array_values($newCodes)), ':id' => $userId]);
            
            return true;
        }
        
        return false;
    }
    
    public function logSecurityEvent($userId, $action, $description) {
        $stmt = $this->db->prepare("
            INSERT INTO security_logs (user_id, action_type, description, ip_address, user_agent) 
            VALUES (:user_id, :action, :description, :ip, :ua)
        ");
        
        $stmt->execute([
            ':user_id' => $userId,
            ':action' => $action,
            ':description' => $description,
            ':ip' => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
            ':ua' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        ]);
    }
}
?>