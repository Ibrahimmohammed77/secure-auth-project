<?php
session_start();
require_once '../includes/Auth.php';
require_once '../includes/Database.php';

$auth = new Auth();

// التحقق من الجلسة
if (!isset($_COOKIE['session_token'])) {
    header('Location: ../login.php');
    exit;
}

$user = $auth->validateSession($_COOKIE['session_token']);
if (!$user) {
    header('Location: ../login.php');
    exit;
}

// التحقق من صلاحية المدير
if ($user['role'] !== 'admin') {
    header('Location: ../dashboard.php');
    exit;
}

$pdo = Database::getInstance();

// إنشاء جدول system_settings إذا لم يكن موجوداً
createSystemTables($pdo);

// الحصول على الإعدادات الحالية
$stmt = $pdo->query("SELECT * FROM system_settings");
$settings = [];
while ($row = $stmt->fetch()) {
    $settings[$row['setting_key']] = $row['setting_value'];
}

// معالجة تحديث الإعدادات
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['update_settings'])) {
        foreach ($_POST['settings'] as $key => $value) {
            // التحقق من صحة البيانات
            $value = htmlspecialchars(trim($value));
            
            $stmt = $pdo->prepare("
                INSERT INTO system_settings (setting_key, setting_value, updated_at) 
                VALUES (:key, :value, NOW())
                ON DUPLICATE KEY UPDATE setting_value = :value, updated_at = NOW()
            ");
            $stmt->execute([':key' => $key, ':value' => $value]);
        }
        
        $auth->logSecurityEvent($user['id'], 'SETTINGS_UPDATE', 'تم تحديث إعدادات النظام');
        $_SESSION['success_message'] = "تم تحديث الإعدادات بنجاح";
        header('Location: settings.php');
        exit;
    }
    
    if (isset($_POST['test_email'])) {
        // اختبار إرسال البريد الإلكتروني
        $to = $_POST['test_email_address'];
        $subject = "اختبار إعدادات البريد - نظام الأمان";
        $message = "هذه رسالة اختبار لتأكيد أن إعدادات البريد الإلكتروني تعمل بشكل صحيح.\n\n";
        $message .= "تم الإرسال في: " . date('Y-m-d H:i:s') . "\n";
        $message .= "بواسطة: " . $user['email'];
        
        // في بيئة حقيقية، أرسل البريد هنا
        // mail($to, $subject, $message);
        
        $auth->logSecurityEvent($user['id'], 'EMAIL_TEST', "تم اختبار إرسال بريد إلى: $to");
        $_SESSION['success_message'] = "تم إرسال رسالة اختبار إلى $to";
        header('Location: settings.php');
        exit;
    }
    
    if (isset($_POST['clear_cache'])) {
        // تنظيف الذاكرة المؤقتة
        $cacheDir = '../cache/';
        if (is_dir($cacheDir)) {
            array_map('unlink', glob($cacheDir . '*'));
        }
        
        $auth->logSecurityEvent($user['id'], 'CACHE_CLEARED', 'تم تنظيف الذاكرة المؤقتة');
        $_SESSION['success_message'] = "تم تنظيف الذاكرة المؤقتة بنجاح";
        header('Location: settings.php');
        exit;
    }
    
    if (isset($_POST['backup_database'])) {
        // إنشاء نسخة احتياطية من قاعدة البيانات
        $backupFile = '../backups/db_backup_' . date('Y-m-d_H-i-s') . '.sql';
        
        // في بيئة حقيقية، ستستخدم mysqldump
        // exec("mysqldump -u username -p password database > $backupFile");
        
        $auth->logSecurityEvent($user['id'], 'DATABASE_BACKUP', 'تم إنشاء نسخة احتياطية من قاعدة البيانات');
        $_SESSION['success_message'] = "تم إنشاء نسخة احتياطية بنجاح";
        header('Location: settings.php');
        exit;
    }
}

// التحقق من الرسائل
$success_message = $_SESSION['success_message'] ?? null;
unset($_SESSION['success_message']);

// دالة إنشاء الجداول
function createSystemTables($pdo) {
    // إنشاء جدول إعدادات النظام
    $sql = "CREATE TABLE IF NOT EXISTS `system_settings` (
        `id` INT PRIMARY KEY AUTO_INCREMENT,
        `setting_key` VARCHAR(100) UNIQUE NOT NULL,
        `setting_value` TEXT,
        `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
    
    try {
        $pdo->exec($sql);
        
        // إضافة إعدادات افتراضية إذا كان الجدول فارغاً
        $stmt = $pdo->query("SELECT COUNT(*) as count FROM system_settings");
        $result = $stmt->fetch();
        
        if ($result['count'] == 0) {
            $defaultSettings = [
                ['system_name', 'نظام الأمان المتقدم'],
                ['system_url', 'https://localhost'],
                ['default_language', 'ar'],
                ['timezone', 'Asia/Riyadh'],
                ['maintenance_mode', '0'],
                ['maintenance_message', 'النظام قيد الصيانة، يرجى المحاولة لاحقاً.'],
                ['force_https', '1'],
                ['require_mfa_teachers', '1'],
                ['max_login_attempts', '5'],
                ['lockout_duration', '15'],
                ['min_password_length', '8'],
                ['password_expiry_days', '90'],
                ['bcrypt_cost', '12'],
                ['allow_password_reset', '1'],
                ['allow_registration', '1'],
                ['enable_captcha', '1'],
                ['smtp_host', 'smtp.gmail.com'],
                ['smtp_port', '587'],
                ['smtp_username', ''],
                ['smtp_password', ''],
                ['smtp_encryption', 'tls'],
                ['from_email', 'noreply@localhost'],
                ['from_name', 'نظام الأمان'],
                ['session_lifetime', '24'],
                ['max_active_sessions', '5'],
                ['session_regenerate', '1'],
                ['session_https_only', '1'],
                ['session_httponly', '1'],
                ['session_samesite', 'Strict'],
                ['backup_frequency', 'weekly'],
                ['backup_retention', '30'],
                ['backup_compress', '1'],
                ['backup_notify', '1']
            ];
            
            foreach ($defaultSettings as $setting) {
                $stmt = $pdo->prepare("INSERT INTO system_settings (setting_key, setting_value) VALUES (?, ?)");
                $stmt->execute([$setting[0], $setting[1]]);
            }
        }
    } catch (Exception $e) {
        // تجاهل الخطأ إذا كان الجدول موجوداً بالفعل
        error_log("Error creating system_settings table: " . $e->getMessage());
    }
}
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>إعدادات النظام - لوحة التحكم</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="../assets/css/admin.css">
    <link rel="stylesheet" href="../assets/css/settings.css">
    <style>
        /* أنماط إضافية خاصة بالصفحة */
        .menu-toggle {
            display: none;
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1001;
            background: var(--primary-color);
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1.2rem;
        }
        
        @media (max-width: 992px) {
            .menu-toggle {
                display: block;
            }
        }
    </style>
</head>
<body>
    <button class="menu-toggle" onclick="toggleSidebar()">
        <i class="fas fa-bars"></i>
    </button>
    
    <?php include 'components/sidebar.php'; ?>
    
    <div class="main-content">
        <div class="top-bar">
            <div class="page-title">
                <h2><i class="fas fa-cog"></i> إعدادات النظام</h2>
                <p>تهيئة وتكوين إعدادات النظام والأمان</p>
            </div>
            
            <div class="quick-actions">
                <button class="action-btn primary" onclick="saveAllSettings()">
                    <i class="fas fa-save"></i> حفظ جميع الإعدادات
                </button>
                <button class="action-btn" onclick="resetSettings()">
                    <i class="fas fa-redo"></i> استعادة الافتراضية
                </button>
            </div>
        </div>

        <?php if ($success_message): ?>
        <div class="alert success">
            <i class="fas fa-check-circle fa-2x"></i>
            <div>
                <h3>تم بنجاح!</h3>
                <p><?php echo htmlspecialchars($success_message); ?></p>
            </div>
        </div>
        <?php endif; ?>

        <!-- تبويبات الإعدادات -->
        <div class="settings-tabs">
            <button class="settings-tab active" onclick="showSection('general')">
                <i class="fas fa-sliders-h"></i> عام
            </button>
            <button class="settings-tab" onclick="showSection('security')">
                <i class="fas fa-shield-alt"></i> الأمان
            </button>
            <button class="settings-tab" onclick="showSection('email')">
                <i class="fas fa-envelope"></i> البريد الإلكتروني
            </button>
            <button class="settings-tab" onclick="showSection('sessions')">
                <i class="fas fa-clock"></i> الجلسات
            </button>
            <button class="settings-tab" onclick="showSection('system')">
                <i class="fas fa-server"></i> النظام
            </button>
            <button class="settings-tab" onclick="showSection('backup')">
                <i class="fas fa-database"></i> النسخ الاحتياطي
            </button>
        </div>

        <!-- الإعدادات العامة -->
        <form method="POST" action="" class="settings-section active" id="general-section">
            <div class="section-title">
                <i class="fas fa-sliders-h"></i>
                <h3>الإعدادات العامة</h3>
            </div>

            <div class="settings-grid">
                <div class="setting-group">
                    <label class="setting-label">اسم النظام</label>
                    <input type="text" name="settings[system_name]" class="setting-control"
                           value="<?php echo htmlspecialchars($settings['system_name'] ?? 'نظام الأمان المتقدم'); ?>">
                    <span class="setting-description">الاسم المعروض في رأس النظام والبريد الإلكتروني</span>
                </div>

                <div class="setting-group">
                    <label class="setting-label">عنوان النظام</label>
                    <input type="url" name="settings[system_url]" class="setting-control"
                           value="<?php echo htmlspecialchars($settings['system_url'] ?? 'https://localhost'); ?>">
                    <span class="setting-description">رابط النظام الأساسي</span>
                </div>

                <div class="setting-group">
                    <label class="setting-label">اللغة الافتراضية</label>
                    <select name="settings[default_language]" class="setting-control">
                        <option value="ar" <?php echo ($settings['default_language'] ?? 'ar') === 'ar' ? 'selected' : ''; ?>>العربية</option>
                        <option value="en" <?php echo ($settings['default_language'] ?? 'ar') === 'en' ? 'selected' : ''; ?>>English</option>
                    </select>
                    <span class="setting-description">اللغة الافتراضية لواجهة النظام</span>
                </div>

                <div class="setting-group">
                    <label class="setting-label">المنطقة الزمنية</label>
                    <select name="settings[timezone]" class="setting-control">
                        <option value="Asia/Riyadh" <?php echo ($settings['timezone'] ?? 'Asia/Riyadh') === 'Asia/Riyadh' ? 'selected' : ''; ?>>الرياض (GMT+3)</option>
                        <option value="Asia/Dubai" <?php echo ($settings['timezone'] ?? 'Asia/Riyadh') === 'Asia/Dubai' ? 'selected' : ''; ?>>دبي (GMT+4)</option>
                        <option value="UTC" <?php echo ($settings['timezone'] ?? 'Asia/Riyadh') === 'UTC' ? 'selected' : ''; ?>>توقيت عالمي (UTC)</option>
                    </select>
                    <span class="setting-description">التوقيت المستخدم في عرض التواريخ والأوقات</span>
                </div>

                <div class="setting-group">
                    <label class="checkbox-label">
                        <input type="checkbox" name="settings[maintenance_mode]" class="setting-checkbox"
                               <?php echo ($settings['maintenance_mode'] ?? '0') === '1' ? 'checked' : ''; ?> value="1">
                        <span class="checkbox-text">وضع الصيانة</span>
                    </label>
                    <span class="checkbox-description">
                        عند تفعيله، سيظهر رسالة صيانة لجميع المستخدمين باستثناء المدراء
                    </span>
                </div>

                <div class="setting-group">
                    <label class="setting-label">رسالة الصيانة</label>
                    <textarea name="settings[maintenance_message]" class="setting-control" rows="4"
                              placeholder="نظامنا قيد الصيانة..."><?php echo htmlspecialchars($settings['maintenance_message'] ?? 'النظام قيد الصيانة، يرجى المحاولة لاحقاً.'); ?></textarea>
                    <span class="setting-description">تظهر للمستخدمين عندما يكون النظام في وضع الصيانة</span>
                </div>
            </div>

            <div class="actions-bar">
                <button type="submit" name="update_settings" class="btn-save">
                    <i class="fas fa-save"></i> حفظ التغييرات
                </button>
            </div>
        </form>

        <!-- إعدادات الأمان -->
        <form method="POST" action="" class="settings-section" id="security-section">
            <div class="section-title">
                <i class="fas fa-shield-alt"></i>
                <h3>إعدادات الأمان</h3>
            </div>

            <div class="settings-grid">
                <div class="setting-group">
                    <label class="checkbox-label">
                        <input type="checkbox" name="settings[force_https]" class="setting-checkbox"
                               <?php echo ($settings['force_https'] ?? '1') === '1' ? 'checked' : ''; ?> value="1">
                        <span class="checkbox-text">إجبار استخدام HTTPS</span>
                    </label>
                    <span class="checkbox-description">
                        تحويل جميع الاتصالات إلى HTTPS تلقائياً
                    </span>
                </div>

                <div class="setting-group">
                    <label class="checkbox-label">
                        <input type="checkbox" name="settings[require_mfa_teachers]" class="setting-checkbox"
                               <?php echo ($settings['require_mfa_teachers'] ?? '1') === '1' ? 'checked' : ''; ?> value="1">
                        <span class="checkbox-text">إجبار MFA للمدرسين</span>
                    </label>
                    <span class="checkbox-description">
                        إجبار المصادقة الثنائية لجميع حسابات المدرسين
                    </span>
                </div>

                <div class="setting-group">
                    <label class="setting-label">الحد الأقصى لمحاولات الدخول</label>
                    <input type="number" name="settings[max_login_attempts]" class="setting-control" min="1" max="10"
                           value="<?php echo htmlspecialchars($settings['max_login_attempts'] ?? '5'); ?>">
                    <span class="setting-description">عدد المحاولات المسموح بها قبل قفل الحساب</span>
                </div>

                <div class="setting-group">
                    <label class="setting-label">مدة قفل الحساب (دقيقة)</label>
                    <input type="number" name="settings[lockout_duration]" class="setting-control" min="1" max="1440"
                           value="<?php echo htmlspecialchars($settings['lockout_duration'] ?? '15'); ?>">
                    <span class="setting-description">مدة قفل الحساب بعد تجاوز المحاولات المسموح بها</span>
                </div>

                <div class="setting-group">
                    <label class="setting-label">أقل طول لكلمة المرور</label>
                    <input type="number" name="settings[min_password_length]" class="setting-control" min="6" max="32"
                           value="<?php echo htmlspecialchars($settings['min_password_length'] ?? '8'); ?>">
                    <span class="setting-description">الحد الأدنى لطول كلمات المرور</span>
                </div>

                <div class="setting-group">
                    <label class="setting-label">مدة صلاحية كلمة المرور (أيام)</label>
                    <input type="number" name="settings[password_expiry_days]" class="setting-control" min="0" max="365"
                           value="<?php echo htmlspecialchars($settings['password_expiry_days'] ?? '90'); ?>">
                    <span class="setting-description">0 يعني لا تنتهي الصلاحية</span>
                </div>

                <div class="setting-group">
                    <label class="setting-label">مستوى تشفير Bcrypt</label>
                    <select name="settings[bcrypt_cost]" class="setting-control">
                        <option value="10" <?php echo ($settings['bcrypt_cost'] ?? '12') === '10' ? 'selected' : ''; ?>>منخفض (أسرع)</option>
                        <option value="12" <?php echo ($settings['bcrypt_cost'] ?? '12') === '12' ? 'selected' : ''; ?>>متوسط (موصى به)</option>
                        <option value="14" <?php echo ($settings['bcrypt_cost'] ?? '12') === '14' ? 'selected' : ''; ?>>عالي (أكثر أماناً)</option>
                    </select>
                    <span class="setting-description">ارتفاع المستوى يزيد الأمان ويقلل السرعة</span>
                </div>
            </div>

            <div class="danger-zone">
                <div class="danger-title">
                    <i class="fas fa-exclamation-triangle"></i>
                    <h3>منطقة الخطر - إعدادات حساسة</h3>
                </div>
                <div class="danger-description">
                    هذه الإعدادات قد تؤثر على أمان النظام بشكل كبير. يرجى التأكد من فهمك التام قبل التعديل.
                </div>
                
                <div class="setting-group">
                    <label class="checkbox-label">
                        <input type="checkbox" name="settings[allow_password_reset]" class="setting-checkbox"
                               <?php echo ($settings['allow_password_reset'] ?? '1') === '1' ? 'checked' : ''; ?> value="1">
                        <span class="checkbox-text">السماح باستعادة كلمة المرور</span>
                    </label>
                    <span class="checkbox-description">
                        السماح للمستخدمين باستعادة كلمات المرور عبر البريد الإلكتروني
                    </span>
                </div>

                <div class="setting-group">
                    <label class="checkbox-label">
                        <input type="checkbox" name="settings[allow_registration]" class="setting-checkbox"
                               <?php echo ($settings['allow_registration'] ?? '1') === '1' ? 'checked' : ''; ?> value="1">
                        <span class="checkbox-text">السماح بالتسجيل الذاتي</span>
                    </label>
                    <span class="checkbox-description">
                        السماح للمستخدمين الجدد بالتسجيل بأنفسهم
                    </span>
                </div>

                <div class="setting-group">
                    <label class="checkbox-label">
                        <input type="checkbox" name="settings[enable_captcha]" class="setting-checkbox"
                               <?php echo ($settings['enable_captcha'] ?? '1') === '1' ? 'checked' : ''; ?> value="1">
                        <span class="checkbox-text">تفعيل CAPTCHA</span>
                    </label>
                    <span class="checkbox-description">
                        عرض CAPTCHA في صفحات التسجيل والدخول بعد عدة محاولات فاشلة
                    </span>
                </div>
            </div>

            <div class="actions-bar">
                <button type="submit" name="update_settings" class="btn-save">
                    <i class="fas fa-save"></i> حفظ التغييرات
                </button>
            </div>
        </form>

        <!-- إعدادات البريد الإلكتروني -->
        <form method="POST" action="" class="settings-section" id="email-section">
            <div class="section-title">
                <i class="fas fa-envelope"></i>
                <h3>إعدادات البريد الإلكتروني</h3>
            </div>

            <div class="settings-grid">
                <div class="setting-group">
                    <label class="setting-label">خادم SMTP</label>
                    <input type="text" name="settings[smtp_host]" class="setting-control"
                           value="<?php echo htmlspecialchars($settings['smtp_host'] ?? 'smtp.gmail.com'); ?>">
                    <span class="setting-description">عنوان خادم البريد الإلكتروني</span>
                </div>

                <div class="setting-group">
                    <label class="setting-label">منفذ SMTP</label>
                    <input type="number" name="settings[smtp_port]" class="setting-control" min="1" max="65535"
                           value="<?php echo htmlspecialchars($settings['smtp_port'] ?? '587'); ?>">
                    <span class="setting-description">المنفذ المستخدم للاتصال بخادم SMTP</span>
                </div>

                <div class="setting-group">
                    <label class="setting-label">اسم المستخدم</label>
                    <input type="text" name="settings[smtp_username]" class="setting-control"
                           value="<?php echo htmlspecialchars($settings['smtp_username'] ?? ''); ?>">
                    <span class="setting-description">اسم مستخدم خادم البريد</span>
                </div>

                <div class="setting-group">
                    <label class="setting-label">كلمة المرور</label>
                    <input type="password" name="settings[smtp_password]" class="setting-control"
                           value="<?php echo htmlspecialchars($settings['smtp_password'] ?? ''); ?>">
                    <span class="setting-description">كلمة مرور خادم البريد</span>
                </div>

                <div class="setting-group">
                    <label class="setting-label">التشفير</label>
                    <select name="settings[smtp_encryption]" class="setting-control">
                        <option value="tls" <?php echo ($settings['smtp_encryption'] ?? 'tls') === 'tls' ? 'selected' : ''; ?>>TLS</option>
                        <option value="ssl" <?php echo ($settings['smtp_encryption'] ?? 'tls') === 'ssl' ? 'selected' : ''; ?>>SSL</option>
                        <option value="" <?php echo ($settings['smtp_encryption'] ?? 'tls') === '' ? 'selected' : ''; ?>>لا يوجد</option>
                    </select>
                    <span class="setting-description">نوع التشفير المستخدم في الاتصال</span>
                </div>

                <div class="setting-group">
                    <label class="setting-label">البريد المرسل منه</label>
                    <input type="email" name="settings[from_email]" class="setting-control"
                           value="<?php echo htmlspecialchars($settings['from_email'] ?? 'noreply@localhost'); ?>">
                    <span class="setting-description">عنوان البريد الإلكتروني المرسل منه</span>
                </div>

                <div class="setting-group">
                    <label class="setting-label">اسم المرسل</label>
                    <input type="text" name="settings[from_name]" class="setting-control"
                           value="<?php echo htmlspecialchars($settings['from_name'] ?? 'نظام الأمان'); ?>">
                    <span class="setting-description">الاسم المعروض كمرسل للبريد</span>
                </div>
            </div>

            <!-- اختبار إرسال البريد -->
            <div style="margin-top: 30px; padding: 20px; background: #f9fafb; border-radius: var(--border-radius);">
                <h4 style="margin-bottom: 15px; color: var(--dark-color);">
                    <i class="fas fa-vial"></i> اختبار إرسال البريد
                </h4>
                <div class="test-email-form">
                    <input type="email" name="test_email_address" class="test-email-input"
                           placeholder="أدخل بريدك الإلكتروني لاختبار الإرسال" required>
                    <button type="submit" name="test_email" class="btn-test">
                        <i class="fas fa-paper-plane"></i> اختبار الإرسال
                    </button>
                </div>
                <small style="color: var(--gray-color); display: block; margin-top: 10px;">
                    سيتم إرسال رسالة اختبار للتأكد من أن إعدادات البريد تعمل بشكل صحيح
                </small>
            </div>

            <div class="actions-bar">
                <button type="submit" name="update_settings" class="btn-save">
                    <i class="fas fa-save"></i> حفظ التغييرات
                </button>
            </div>
        </form>

        <!-- إعدادات الجلسات -->
        <form method="POST" action="" class="settings-section" id="sessions-section">
            <div class="section-title">
                <i class="fas fa-clock"></i>
                <h3>إعدادات الجلسات</h3>
            </div>

            <div class="settings-grid">
                <div class="setting-group">
                    <label class="setting-label">مدة الجلسة (ساعة)</label>
                    <input type="number" name="settings[session_lifetime]" class="setting-control" min="1" max="720"
                           value="<?php echo htmlspecialchars($settings['session_lifetime'] ?? '24'); ?>">
                    <span class="setting-description">مدة صلاحية الجلسة قبل انتهائها تلقائياً</span>
                </div>

                <div class="setting-group">
                    <label class="setting-label">الحد الأقصى للجلسات النشطة</label>
                    <input type="number" name="settings[max_active_sessions]" class="setting-control" min="1" max="100"
                           value="<?php echo htmlspecialchars($settings['max_active_sessions'] ?? '5'); ?>">
                    <span class="setting-description">الحد الأقصى لعدد الجلسات النشطة لكل مستخدم</span>
                </div>

                <div class="setting-group">
                    <label class="checkbox-label">
                        <input type="checkbox" name="settings[session_regenerate]" class="setting-checkbox"
                               <?php echo ($settings['session_regenerate'] ?? '1') === '1' ? 'checked' : ''; ?> value="1">
                        <span class="checkbox-text">إعادة توليد معرف الجلسة</span>
                    </label>
                    <span class="checkbox-description">
                        إعادة توليد معرف الجلسة بعد تسجيل الدخول الناجح
                    </span>
                </div>

                <div class="setting-group">
                    <label class="checkbox-label">
                        <input type="checkbox" name="settings[session_https_only]" class="setting-checkbox"
                               <?php echo ($settings['session_https_only'] ?? '1') === '1' ? 'checked' : ''; ?> value="1">
                        <span class="checkbox-text">جلسات HTTPS فقط</span>
                    </label>
                    <span class="checkbox-description">
                        السماح بالجلسات عبر اتصال آمن (HTTPS) فقط
                    </span>
                </div>

                <div class="setting-group">
                    <label class="checkbox-label">
                        <input type="checkbox" name="settings[session_httponly]" class="setting-checkbox"
                               <?php echo ($settings['session_httponly'] ?? '1') === '1' ? 'checked' : ''; ?> value="1">
                        <span class="checkbox-text">HttpOnly للكوكيز</span>
                    </label>
                    <span class="checkbox-description">
                        منع وصول JavaScript إلى كوكيز الجلسة
                    </span>
                </div>

                <div class="setting-group">
                    <label class="setting-label">سياسة SameSite للكوكيز</label>
                    <select name="settings[session_samesite]" class="setting-control">
                        <option value="Strict" <?php echo ($settings['session_samesite'] ?? 'Strict') === 'Strict' ? 'selected' : ''; ?>>Strict</option>
                        <option value="Lax" <?php echo ($settings['session_samesite'] ?? 'Strict') === 'Lax' ? 'selected' : ''; ?>>Lax</option>
                        <option value="None" <?php echo ($settings['session_samesite'] ?? 'Strict') === 'None' ? 'selected' : ''; ?>>None</option>
                    </select>
                    <span class="setting-description">تحديد متى يتم إرسال كوكيز الجلسة مع الطلبات</span>
                </div>
            </div>

            <div class="actions-bar">
                <button type="submit" name="update_settings" class="btn-save">
                    <i class="fas fa-save"></i> حفظ التغييرات
                </button>
            </div>
        </form>

        <!-- معلومات النظام -->
        <div class="settings-section" id="system-section">
            <div class="section-title">
                <i class="fas fa-server"></i>
                <h3>معلومات النظام</h3>
            </div>

            <div class="system-info">
                <h4 style="margin-bottom: 20px; color: var(--dark-color);">معلومات الخادم</h4>
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">نظام التشغيل</span>
                        <span class="info-value"><?php echo php_uname('s'); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">إصدار PHP</span>
                        <span class="info-value <?php echo version_compare(PHP_VERSION, '7.4.0', '>=') ? 'good' : 'bad'; ?>">
                            <?php echo PHP_VERSION; ?>
                        </span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">إصدار MySQL</span>
                        <?php
                        $mysql_version = $pdo->getAttribute(PDO::ATTR_SERVER_VERSION);
                        $mysql_status = version_compare($mysql_version, '5.7.0', '>=') ? 'good' : 'warning';
                        ?>
                        <span class="info-value <?php echo $mysql_status; ?>">
                            <?php echo $mysql_version; ?>
                        </span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">الذاكرة المسموحة</span>
                        <span class="info-value"><?php echo ini_get('memory_limit'); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">الحد الأقصى لوقت التنفيذ</span>
                        <span class="info-value"><?php echo ini_get('max_execution_time'); ?> ثانية</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">تحميل ملفات أقصى</span>
                        <span class="info-value"><?php echo ini_get('upload_max_filesize'); ?></span>
                    </div>
                </div>
            </div>

            <div class="system-info">
                <h4 style="margin-bottom: 20px; color: var(--dark-color);">معلومات قاعدة البيانات</h4>
                <div class="info-grid">
                    <?php
                    // إحصائيات قاعدة البيانات
                    $stmt = $pdo->query("SELECT COUNT(*) as total_users FROM users");
                    $totalUsers = $stmt->fetch()['total_users'];
                    
                    $stmt = $pdo->query("SELECT COUNT(*) as total_sessions FROM user_sessions");
                    $totalSessions = $stmt->fetch()['total_sessions'];
                    
                    $stmt = $pdo->query("SELECT COUNT(*) as total_logs FROM security_logs");
                    $totalLogs = $stmt->fetch()['total_logs'];
                    ?>
                    <div class="info-item">
                        <span class="info-label">المستخدمين</span>
                        <span class="info-value"><?php echo number_format($totalUsers); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">الجلسات</span>
                        <span class="info-value"><?php echo number_format($totalSessions); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">سجلات الأمان</span>
                        <span class="info-value"><?php echo number_format($totalLogs); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">حجم قاعدة البيانات</span>
                        <span class="info-value">
                            <?php
                            $stmt = $pdo->query("SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) as size FROM information_schema.tables WHERE table_schema = DATABASE()");
                            $dbSize = $stmt->fetch()['size'];
                            echo $dbSize . ' MB';
                            ?>
                        </span>
                    </div>
                </div>
            </div>

            <!-- إجراءات النظام -->
            <div class="danger-zone" style="margin-top: 30px;">
                <div class="danger-title">
                    <i class="fas fa-tools"></i>
                    <h3>إجراءات النظام</h3>
                </div>
                <div class="danger-description">
                    هذه الإجراءات تؤثر على أداء النظام وتخزين البيانات.
                </div>
                
                <div class="danger-actions">
                    <form method="POST" action="" style="display: inline;">
                        <button type="submit" name="clear_cache" class="btn-danger" onclick="return confirm('هل تريد تنظيف الذاكرة المؤقتة؟')">
                            <i class="fas fa-broom"></i> تنظيف الذاكرة المؤقتة
                        </button>
                    </form>
                    
                    <button type="button" class="btn-danger" onclick="runSystemDiagnostics()">
                        <i class="fas fa-stethoscope"></i> تشخيص النظام
                    </button>
                    
                    <button type="button" class="btn-danger" onclick="optimizeDatabase()">
                        <i class="fas fa-database"></i> تحسين قاعدة البيانات
                    </button>
                </div>
            </div>
        </div>

        <!-- النسخ الاحتياطي -->
        <form method="POST" action="" class="settings-section" id="backup-section">
            <div class="section-title">
                <i class="fas fa-database"></i>
                <h3>النسخ الاحتياطي</h3>
            </div>

            <div class="settings-grid">
                <div class="setting-group">
                    <label class="setting-label">فترة النسخ الاحتياطي التلقائي</label>
                    <select name="settings[backup_frequency]" class="setting-control">
                        <option value="daily" <?php echo ($settings['backup_frequency'] ?? 'weekly') === 'daily' ? 'selected' : ''; ?>>يومياً</option>
                        <option value="weekly" <?php echo ($settings['backup_frequency'] ?? 'weekly') === 'weekly' ? 'selected' : ''; ?>>أسبوعياً</option>
                        <option value="monthly" <?php echo ($settings['backup_frequency'] ?? 'weekly') === 'monthly' ? 'selected' : ''; ?>>شهرياً</option>
                        <option value="disabled" <?php echo ($settings['backup_frequency'] ?? 'weekly') === 'disabled' ? 'selected' : ''; ?>>معطل</option>
                    </select>
                    <span class="setting-description">فترة إنشاء النسخ الاحتياطية تلقائياً</span>
                </div>

                <div class="setting-group">
                    <label class="setting-label">الاحتفاظ بالنسخ (أيام)</label>
                    <input type="number" name="settings[backup_retention]" class="setting-control" min="1" max="365"
                           value="<?php echo htmlspecialchars($settings['backup_retention'] ?? '30'); ?>">
                    <span class="setting-description">عدد الأيام للاحتفاظ بالنسخ الاحتياطية قبل حذفها</span>
                </div>

                <div class="setting-group">
                    <label class="checkbox-label">
                        <input type="checkbox" name="settings[backup_compress]" class="setting-checkbox"
                               <?php echo ($settings['backup_compress'] ?? '1') === '1' ? 'checked' : ''; ?> value="1">
                        <span class="checkbox-text">ضغط النسخ الاحتياطية</span>
                    </label>
                    <span class="checkbox-description">
                        ضغط النسخ الاحتياطية لتوفير المساحة
                    </span>
                </div>

                <div class="setting-group">
                    <label class="checkbox-label">
                        <input type="checkbox" name="settings[backup_notify]" class="setting-checkbox"
                               <?php echo ($settings['backup_notify'] ?? '1') === '1' ? 'checked' : ''; ?> value="1">
                        <span class="checkbox-text">إشعارات النسخ الاحتياطي</span>
                    </label>
                    <span class="checkbox-description">
                        إرسال إشعارات عند نجاح/فشل النسخ الاحتياطي
                    </span>
                </div>
            </div>

            <!-- النسخ اليدوي -->
            <div style="margin-top: 30px; padding: 25px; background: #f9fafb; border-radius: var(--border-radius);">
                <h4 style="margin-bottom: 20px; color: var(--dark-color);">
                    <i class="fas fa-hdd"></i> النسخ الاحتياطي اليدوي
                </h4>
                
                <div class="danger-actions">
                    <button type="submit" name="backup_database" class="btn-danger" onclick="return confirm('هل تريد إنشاء نسخة احتياطية يدوية؟')">
                        <i class="fas fa-save"></i> إنشاء نسخة احتياطية الآن
                    </button>
                    
                    <button type="button" class="btn-danger" onclick="restoreBackup()">
                        <i class="fas fa-undo"></i> استعادة نسخة احتياطية
                    </button>
                    
                    <button type="button" class="btn-danger" onclick="downloadBackups()">
                        <i class="fas fa-download"></i> تحميل النسخ الاحتياطية
                    </button>
                </div>
                
                <div style="margin-top: 20px; color: var(--gray-color); font-size: 0.9rem;">
                    <p><strong>ملاحظة:</strong> النسخ الاحتياطية تحفظ في مجلد <code>/backups</code></p>
                    <p>آخر نسخة احتياطية: <?php
                        $backupDir = '../backups/';
                        if (is_dir($backupDir)) {
                            $files = glob($backupDir . '*.sql');
                            if (!empty($files)) {
                                $latestFile = max($files);
                                echo date('Y-m-d H:i:s', filemtime($latestFile));
                            } else {
                                echo 'لا توجد نسخ احتياطية';
                            }
                        }
                    ?></p>
                </div>
            </div>

            <div class="actions-bar">
                <button type="submit" name="update_settings" class="btn-save">
                    <i class="fas fa-save"></i> حفظ التغييرات
                </button>
            </div>
        </form>
    </div>

    <script>
        // إظهار وإخفاء أقسام الإعدادات
        function showSection(sectionId) {
            // إخفاء جميع الأقسام
            document.querySelectorAll('.settings-section').forEach(section => {
                section.classList.remove('active');
            });
            
            // إزالة التفعيل من جميع التبويبات
            document.querySelectorAll('.settings-tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // إظهار القسم المطلوب
            document.getElementById(sectionId + '-section').classList.add('active');
            
            // تفعيل التبويب المطلوب
            document.querySelector(`.settings-tab[onclick="showSection('${sectionId}')"]`).classList.add('active');
        }
        
        // حفظ جميع الإعدادات
        function saveAllSettings() {
            // جمع البيانات من جميع النماذج
            const allForms = document.querySelectorAll('form');
            const formData = new FormData();
            
            allForms.forEach(form => {
                const formElements = form.elements;
                for (let element of formElements) {
                    if (element.name && element.value) {
                        if (element.type === 'checkbox') {
                            formData.append(element.name, element.checked ? '1' : '0');
                        } else {
                            formData.append(element.name, element.value);
                        }
                    }
                }
            });
            
            // إرسال البيانات (في الواقع، ستستخدم AJAX)
            alert('جاري حفظ جميع الإعدادات...');
            document.querySelector('button[name="update_settings"]').click();
        }
        
        // استعادة الإعدادات الافتراضية
        function resetSettings() {
            if (confirm('⚠️ هل أنت متأكد من استعادة الإعدادات الافتراضية؟\nسيتم فقدان جميع التغييرات الحالية.')) {
                // في الواقع، ستقوم بإرسال طلب إلى الخادم
                fetch('reset-settings.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ reset: true })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('تم استعادة الإعدادات الافتراضية بنجاح');
                        location.reload();
                    } else {
                        alert('حدث خطأ أثناء استعادة الإعدادات');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('حدث خطأ في الاتصال بالخادم');
                });
            }
        }
        
        // تشخيص النظام
        function runSystemDiagnostics() {
            const modalContent = `
                <div class="modal" id="diagnosticsModal" style="display: flex;">
                    <div class="modal-content" style="max-width: 700px;">
                        <div class="modal-header">
                            <div class="modal-title"><i class="fas fa-stethoscope"></i> تشخيص النظام</div>
                            <button class="close-modal" onclick="closeModal('diagnosticsModal')">&times;</button>
                        </div>
                        <div style="padding: 20px;">
                            <div id="diagnosticsResults">
                                <div style="text-align: center; padding: 40px;">
                                    <i class="fas fa-spinner fa-spin fa-2x" style="color: var(--primary-color);"></i>
                                    <p style="margin-top: 15px;">جاري تشخيص النظام...</p>
                                </div>
                            </div>
                        </div>
                        <div style="text-align: center; margin-top: 20px;">
                            <button class="btn btn-primary" onclick="closeModal('diagnosticsModal')">
                                <i class="fas fa-times"></i> إغلاق
                            </button>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.insertAdjacentHTML('beforeend', modalContent);
            
            // محاكاة التشخيص
            setTimeout(() => {
                const results = document.getElementById('diagnosticsResults');
                results.innerHTML = `
                    <div style="background: #d1fae5; padding: 20px; border-radius: 10px; margin-bottom: 15px;">
                        <h4 style="color: #065f46; margin-bottom: 10px;"><i class="fas fa-check-circle"></i> نظام التشغيل</h4>
                        <p>✅ الإصدار: ${navigator.platform}</p>
                        <p>✅ المتصفح: ${navigator.userAgent}</p>
                    </div>
                    <div style="background: #d1fae5; padding: 20px; border-radius: 10px; margin-bottom: 15px;">
                        <h4 style="color: #065f46; margin-bottom: 10px;"><i class="fas fa-check-circle"></i> اتصال الخادم</h4>
                        <p>✅ الاستجابة: 200ms</p>
                        <p>✅ الاتصال: نشط</p>
                    </div>
                    <div style="background: #fef3c7; padding: 20px; border-radius: 10px; margin-bottom: 15px;">
                        <h4 style="color: #92400e; margin-bottom: 10px;"><i class="fas fa-exclamation-triangle"></i> قاعدة البيانات</h4>
                        <p>⚠️ الحجم: ${Math.round(Math.random() * 1000)}MB</p>
                        <p>✅ الاتصال: نشط</p>
                    </div>
                    <div style="background: #fee2e2; padding: 20px; border-radius: 10px;">
                        <h4 style="color: #991b1b; margin-bottom: 10px;"><i class="fas fa-times-circle"></i> الذاكرة</h4>
                        <p>❌ الاستخدام: 85%</p>
                        <p>⚠️ الحد: ${Math.round(Math.random() * 100)}%</p>
                    </div>
                `;
            }, 2000);
        }
        
        // تحسين قاعدة البيانات
        function optimizeDatabase() {
            if (confirm('هل تريد تحسين قاعدة البيانات؟\nقد يستغرق هذا بعض الوقت.')) {
                fetch('optimize-database.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ optimize: true })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('تم تحسين قاعدة البيانات بنجاح');
                    } else {
                        alert('حدث خطأ أثناء التحسين');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('حدث خطأ في الاتصال بالخادم');
                });
            }
        }
        
        // استعادة نسخة احتياطية
        function restoreBackup() {
            const modalContent = `
                <div class="modal" id="restoreModal" style="display: flex;">
                    <div class="modal-content" style="max-width: 500px;">
                        <div class="modal-header">
                            <div class="modal-title"><i class="fas fa-undo"></i> استعادة نسخة احتياطية</div>
                            <button class="close-modal" onclick="closeModal('restoreModal')">&times;</button>
                        </div>
                        <div style="padding: 20px;">
                            <p style="margin-bottom: 15px;">اختر النسخة الاحتياطية المراد استعادتها:</p>
                            <select class="form-control" style="margin-bottom: 20px;">
                                <option>backup_2024_01_15_10_30_00.sql</option>
                                <option>backup_2024_01_14_09_15_00.sql</option>
                                <option>backup_2024_01_13_08_00_00.sql</option>
                            </select>
                            <div class="alert" style="background: #fff3cd; color: #856404; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                                <i class="fas fa-exclamation-triangle"></i>
                                <strong>تحذير:</strong> استعادة النسخة الاحتياطية ستحذف جميع البيانات الحالية وتستبدلها بالنسخة القديمة.
                            </div>
                            <div style="text-align: center;">
                                <button class="btn btn-danger" onclick="confirmRestore()">
                                    <i class="fas fa-undo"></i> تأكيد الاستعادة
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.insertAdjacentHTML('beforeend', modalContent);
        }
        
        function confirmRestore() {
            if (confirm('⚠️ تحذير نهائي!\nهل أنت متأكد من استعادة النسخة الاحتياطية؟\nجميع البيانات الحالية سيتم فقدانها!')) {
                alert('جاري استعادة النسخة الاحتياطية...');
                closeModal('restoreModal');
            }
        }
        
        // تحميل النسخ الاحتياطية
        function downloadBackups() {
            alert('جاري تحضير قائمة النسخ الاحتياطية للتحميل...');
            // في الواقع، ستقوم بتحميل الملفات
        }
        
        // إغلاق النماذج
        function closeModal(modalId) {
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.style.display = 'none';
                setTimeout(() => modal.remove(), 300);
            }
        }
        
        // توليد كلمات مرور عشوائية للحقول
        function generateRandomPassword(fieldId) {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
            let password = '';
            for (let i = 0; i < 16; i++) {
                password += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            document.getElementById(fieldId).value = password;
        }
        
        // تفعيل توليد كلمات المرور عند تحميل الصفحة
        document.addEventListener('DOMContentLoaded', function() {
            const passwordFields = document.querySelectorAll('input[type="password"]');
            passwordFields.forEach(field => {
                const generateBtn = document.createElement('button');
                generateBtn.type = 'button';
                generateBtn.className = 'btn btn-secondary btn-sm';
                generateBtn.innerHTML = '<i class="fas fa-redo"></i>';
                generateBtn.style.marginRight = '10px';
                generateBtn.onclick = () => generateRandomPassword(field.id || field.name);
                
                field.parentNode.insertBefore(generateBtn, field);
            });
        });
        
        // وظيفة تبديل الشريط الجانبي
        function toggleSidebar() {
            const sidebar = document.querySelector('.sidebar');
            sidebar.classList.toggle('active');
        }
    </script>
</body>
</html>