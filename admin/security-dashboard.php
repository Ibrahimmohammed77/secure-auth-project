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

// الحصول على إحصائيات النظام
$pdo = Database::getInstance();

// إحصائيات المستخدمين
$stmt = $pdo->query("
    SELECT 
        COUNT(*) as total_users,
        SUM(CASE WHEN role = 'student' THEN 1 ELSE 0 END) as students,
        SUM(CASE WHEN role = 'teacher' THEN 1 ELSE 0 END) as teachers,
        SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as admins,
        SUM(CASE WHEN mfa_enabled = TRUE THEN 1 ELSE 0 END) as mfa_enabled,
        SUM(CASE WHEN is_active = FALSE THEN 1 ELSE 0 END) as inactive_users,
        SUM(CASE WHEN account_locked_until IS NOT NULL AND account_locked_until > NOW() THEN 1 ELSE 0 END) as locked_accounts
    FROM users
");
$userStats = $stmt->fetch();

// إحصائيات محاولات الدخول (آخر 24 ساعة)
$stmt = $pdo->query("
    SELECT 
        COUNT(*) as total_attempts,
        SUM(CASE WHEN attempt_status = 'success' THEN 1 ELSE 0 END) as successful,
        SUM(CASE WHEN attempt_status = 'wrong_password' THEN 1 ELSE 0 END) as failed,
        SUM(CASE WHEN attempt_status = 'account_locked' THEN 1 ELSE 0 END) as locked,
        SUM(CASE WHEN attempt_status = 'mfa_failed' THEN 1 ELSE 0 END) as mfa_failed,
        DATE_FORMAT(attempted_at, '%H:00') as hour,
        COUNT(*) as attempts_per_hour
    FROM login_attempts 
    WHERE attempted_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    GROUP BY hour
    ORDER BY hour
");
$hourlyStats = $stmt->fetchAll();

// تجميع إحصائيات ساعة
$hourlyData = [];
foreach ($hourlyStats as $stat) {
    $hourlyData[] = [
        'hour' => $stat['hour'],
        'attempts' => $stat['attempts_per_hour']
    ];
}

// إحصائيات إجمالية لـ24 ساعة
$stmt = $pdo->query("
    SELECT 
        COUNT(*) as total_attempts,
        SUM(CASE WHEN attempt_status = 'success' THEN 1 ELSE 0 END) as successful,
        SUM(CASE WHEN attempt_status = 'wrong_password' THEN 1 ELSE 0 END) as failed,
        SUM(CASE WHEN attempt_status = 'account_locked' THEN 1 ELSE 0 END) as locked,
        SUM(CASE WHEN attempt_status = 'mfa_failed' THEN 1 ELSE 0 END) as mfa_failed
    FROM login_attempts 
    WHERE attempted_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
");
$loginStats = $stmt->fetch();

// أكثر الحسابات استهدافًا
$stmt = $pdo->query("
    SELECT 
        email,
        COUNT(*) as attack_count,
        MAX(attempted_at) as last_attempt,
        MIN(attempted_at) as first_attempt,
        GROUP_CONCAT(DISTINCT ip_address SEPARATOR ', ') as attacking_ips
    FROM login_attempts 
    WHERE attempt_status = 'wrong_password' 
    AND attempted_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    GROUP BY email 
    HAVING COUNT(*) > 3
    ORDER BY attack_count DESC 
    LIMIT 10
");
$targetedAccounts = $stmt->fetchAll();

// عناوين IP مشبوهة
$stmt = $pdo->query("
    SELECT 
        ip_address,
        COUNT(DISTINCT email) as distinct_accounts,
        COUNT(*) as total_attempts,
        GROUP_CONCAT(DISTINCT email SEPARATOR ', ') as targeted_emails,
        MAX(attempted_at) as last_attempt
    FROM login_attempts
    WHERE attempted_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
    AND attempt_status = 'wrong_password'
    GROUP BY ip_address
    HAVING COUNT(DISTINCT email) > 2 OR COUNT(*) > 8
    ORDER BY total_attempts DESC
    LIMIT 15
");
$suspiciousIPs = $stmt->fetchAll();

// أحداث الأمان الأخيرة
$stmt = $pdo->query("
    SELECT 
        sl.*, 
        u.email,
        u.role,
        DATE_FORMAT(sl.created_at, '%Y-%m-%d %H:%i:%s') as formatted_time
    FROM security_logs sl
    LEFT JOIN users u ON sl.user_id = u.id
    WHERE sl.created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    ORDER BY sl.created_at DESC 
    LIMIT 25
");
$recentEvents = $stmt->fetchAll();

// معالجة الإجراءات
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['block_ip'])) {
        $ip = filter_var($_POST['ip_address'], FILTER_VALIDATE_IP);
        $reason = htmlspecialchars($_POST['reason']);
        
        if ($ip) {
            $stmt = $pdo->prepare("
                INSERT INTO blocked_ips (ip_address, reason, blocked_by, blocked_at, expires_at) 
                VALUES (:ip, :reason, :user_id, NOW(), DATE_ADD(NOW(), INTERVAL 7 DAY))
            ");
            $stmt->execute([
                ':ip' => $ip,
                ':reason' => $reason,
                ':user_id' => $user['id']
            ]);
            
            $auth->logSecurityEvent($user['id'], 'IP_BLOCKED', "تم حظر IP: $ip - السبب: $reason");
            
            $_SESSION['success_message'] = "تم حظر عنوان IP $ip بنجاح";
        }
        
        header('Location: security-dashboard.php');
        exit;
    }
    
    if (isset($_POST['clear_logs'])) {
        $days = intval($_POST['days']);
        if ($days > 0) {
            $stmt = $pdo->prepare("DELETE FROM security_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)");
            $stmt->execute([$days]);
            
            $_SESSION['success_message'] = "تم مسح سجلات الأمان الأقدم من $days أيام";
        }
        header('Location: security-dashboard.php');
        exit;
    }
    
    if (isset($_POST['send_alert'])) {
        $email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
        $message = htmlspecialchars($_POST['message']);
        
        if ($email) {
            $auth->logSecurityEvent($user['id'], 'ALERT_SENT', "تم إرسال تنبيه إلى: $email - الرسالة: $message");
            
            $_SESSION['success_message'] = "تم إرسال التنبيه إلى $email";
        }
        header('Location: security-dashboard.php');
        exit;
    }
}

// التحقق من الرسائل الناجحة
$success_message = $_SESSION['success_message'] ?? null;
unset($_SESSION['success_message']);

$page_title = "لوحة تحكم الأمان المتقدمة";
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $page_title; ?> - الإدارة</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="../assets/css/admin.css">
    <style>
        /* Additional inline styles specific to this page */
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
        <!-- شريط الأدوات العلوي -->
        <div class="top-bar">
            <div class="page-title">
                <h2><i class="fas fa-shield-alt"></i> لوحة تحكم الأمان</h2>
                <p>مراقبة وتحليل أنشطة الأمان في الوقت الحقيقي</p>
            </div>
            
            <div class="quick-actions">
                <button class="action-btn primary" onclick="refreshDashboard()">
                    <i class="fas fa-sync-alt"></i> تحديث البيانات
                </button>
                <button class="action-btn danger" onclick="openModal('clearLogsModal')">
                    <i class="fas fa-trash-alt"></i> تنظيف السجلات
                </button>
                <button class="action-btn primary" onclick="generateReport()">
                    <i class="fas fa-download"></i> تصدير تقرير
                </button>
            </div>
        </div>

        <!-- رسالة النجاح -->
        <?php if ($success_message): ?>
        <div class="alert success">
            <i class="fas fa-check-circle fa-2x"></i>
            <div>
                <h3>تم بنجاح!</h3>
                <p><?php echo htmlspecialchars($success_message); ?></p>
            </div>
        </div>
        <?php endif; ?>

        <!-- الشبكة الإحصائية -->
        <div class="stats-grid">
            <!-- بطاقة المستخدمين -->
            <div class="stat-card">
                <div class="stat-header">
                    <div>
                        <div class="stat-value"><?php echo number_format($userStats['total_users']); ?></div>
                        <div class="stat-label">إجمالي المستخدمين</div>
                    </div>
                    <div class="stat-icon users">
                        <i class="fas fa-users"></i>
                    </div>
                </div>
                <div class="stat-details">
                    <div>👨‍🎓 طلاب: <?php echo number_format($userStats['students']); ?></div>
                    <div>👨‍🏫 مدرسون: <?php echo number_format($userStats['teachers']); ?></div>
                    <div>👑 مدراء: <?php echo number_format($userStats['admins']); ?></div>
                </div>
            </div>

            <!-- بطاقة الأمان -->
            <div class="stat-card">
                <div class="stat-header">
                    <div>
                        <div class="stat-value"><?php echo number_format($userStats['mfa_enabled']); ?></div>
                        <div class="stat-label">مفعلين MFA</div>
                    </div>
                    <div class="stat-icon mfa">
                        <i class="fas fa-lock"></i>
                    </div>
                </div>
                <div class="stat-trend trend-up">
                    <i class="fas fa-arrow-up"></i>
                    <?php echo round(($userStats['mfa_enabled'] / max($userStats['total_users'], 1)) * 100, 1); ?>%
                </div>
                <div class="stat-details">
                    <div>نسبة التفعيل: <?php echo round(($userStats['mfa_enabled'] / max($userStats['total_users'], 1)) * 100, 1); ?>%</div>
                </div>
            </div>

            <!-- بطاقة المحاولات -->
            <div class="stat-card">
                <div class="stat-header">
                    <div>
                        <div class="stat-value"><?php echo number_format($loginStats['total_attempts']); ?></div>
                        <div class="stat-label">محاولات دخول (24 ساعة)</div>
                    </div>
                    <div class="stat-icon attacks">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                </div>
                <div class="stat-trend <?php echo $loginStats['failed'] > 50 ? 'trend-down' : 'trend-up'; ?>">
                    <?php if ($loginStats['failed'] > 50): ?>
                    <i class="fas fa-arrow-down"></i> مرتفع
                    <?php else: ?>
                    <i class="fas fa-arrow-up"></i> طبيعي
                    <?php endif; ?>
                </div>
                <div class="stat-details">
                    <div>✅ ناجح: <?php echo number_format($loginStats['successful']); ?></div>
                    <div>❌ فاشل: <?php echo number_format($loginStats['failed']); ?></div>
                </div>
            </div>

            <!-- بطاقة الحسابات المقفلة -->
            <div class="stat-card">
                <div class="stat-header">
                    <div>
                        <div class="stat-value"><?php echo number_format($userStats['locked_accounts']); ?></div>
                        <div class="stat-label">حسابات مقفلة</div>
                    </div>
                    <div class="stat-icon locked">
                        <i class="fas fa-ban"></i>
                    </div>
                </div>
                <div class="stat-details">
                    <div>⚠️ نشط حالياً</div>
                    <div>آخر تحديث: <?php echo date('H:i'); ?></div>
                </div>
            </div>
        </div>

        <!-- المخططات -->
        <div class="charts-grid">
            <div class="chart-container">
                <div class="chart-title">📈 نشاط محاولات الدخول (24 ساعة)</div>
                <canvas id="loginActivityChart"></canvas>
            </div>
            <div class="chart-container">
                <div class="chart-title">🎯 توزيع المحاولات</div>
                <canvas id="attemptsDistributionChart"></canvas>
            </div>
        </div>

        <!-- قسم الحسابات المستهدفة -->
        <div class="section">
            <div class="section-header">
                <div class="section-title">
                    <i class="fas fa-crosshairs"></i>
                    <h3>الحسابات المستهدفة</h3>
                    <span class="status-badge <?php echo count($targetedAccounts) > 5 ? 'status-critical' : 'status-medium'; ?>">
                        <?php echo count($targetedAccounts); ?> حساب
                    </span>
                </div>
                <div class="section-actions">
                    <button class="btn btn-info btn-sm" onclick="exportTargetedAccounts()">
                        <i class="fas fa-download"></i> تصدير
                    </button>
                </div>
            </div>
            
            <div class="table-responsive">
                <table class="table">
                    <thead>
                        <tr>
                            <th>البريد الإلكتروني</th>
                            <th>عدد المحاولات</th>
                            <th>عناوين IP المهاجمة</th>
                            <th>أول/آخر محاولة</th>
                            <th>مستوى الخطورة</th>
                            <th>الإجراءات</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($targetedAccounts)): ?>
                        <tr>
                            <td colspan="6" style="text-align: center; padding: 40px; color: var(--gray-color);">
                                <i class="fas fa-check-circle fa-2x" style="color: var(--secondary-color); margin-bottom: 15px;"></i>
                                <p>لا توجد حسابات مستهدفة في آخر 24 ساعة</p>
                            </td>
                        </tr>
                        <?php else: ?>
                            <?php foreach ($targetedAccounts as $account): 
                                $riskLevel = $account['attack_count'] > 20 ? 'critical' : ($account['attack_count'] > 10 ? 'high' : 'medium');
                            ?>
                            <tr>
                                <td>
                                    <strong><?php echo htmlspecialchars($account['email']); ?></strong>
                                </td>
                                <td>
                                    <span class="status-badge status-<?php echo $riskLevel; ?>">
                                        <?php echo $account['attack_count']; ?> محاولة
                                    </span>
                                </td>
                                <td>
                                    <small><?php echo htmlspecialchars(substr($account['attacking_ips'], 0, 30)); ?>...</small>
                                </td>
                                <td>
                                    <div style="font-size: 0.9rem;">
                                        <div>أولاً: <?php echo date('H:i', strtotime($account['first_attempt'])); ?></div>
                                        <div>أخيراً: <?php echo date('H:i', strtotime($account['last_attempt'])); ?></div>
                                    </div>
                                </td>
                                <td>
                                    <?php if ($riskLevel == 'critical'): ?>
                                    <span class="status-badge status-critical"><i class="fas fa-exclamation-triangle"></i> حرج</span>
                                    <?php elseif ($riskLevel == 'high'): ?>
                                    <span class="status-badge status-high"><i class="fas fa-exclamation-circle"></i> عالي</span>
                                    <?php else: ?>
                                    <span class="status-badge status-medium"><i class="fas fa-info-circle"></i> متوسط</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <button class="btn btn-warning btn-sm" onclick="sendAlertToUser('<?php echo htmlspecialchars($account['email']); ?>')">
                                        <i class="fas fa-bell"></i> تنبيه
                                    </button>
                                    <button class="btn btn-secondary btn-sm" onclick="viewUserDetails('<?php echo htmlspecialchars($account['email']); ?>')">
                                        <i class="fas fa-eye"></i> عرض
                                    </button>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- قسم عناوين IP المشبوهة -->
        <div class="section">
            <div class="section-header">
                <div class="section-title">
                    <i class="fas fa-network-wired"></i>
                    <h3>عناوين IP المشبوهة</h3>
                    <span class="status-badge <?php echo count($suspiciousIPs) > 10 ? 'status-critical' : 'status-high'; ?>">
                        <?php echo count($suspiciousIPs); ?> عنوان
                    </span>
                </div>
                <div class="section-actions">
                    <button class="btn btn-danger btn-sm" onclick="openModal('blockIPModal')">
                        <i class="fas fa-ban"></i> حظر IP يدوياً
                    </button>
                </div>
            </div>
            
            <div class="table-responsive">
                <table class="table">
                    <thead>
                        <tr>
                            <th>عنوان IP</th>
                            <th>الحسابات المستهدفة</th>
                            <th>إجمالي المحاولات</th>
                            <th>آخر محاولة</th>
                            <th>مستوى التهديد</th>
                            <th>الإجراءات</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($suspiciousIPs)): ?>
                        <tr>
                            <td colspan="6" style="text-align: center; padding: 40px; color: var(--gray-color);">
                                <i class="fas fa-shield-alt fa-2x" style="color: var(--secondary-color); margin-bottom: 15px;"></i>
                                <p>لا توجد عناوين IP مشبوهة في آخر ساعة</p>
                            </td>
                        </tr>
                        <?php else: ?>
                            <?php foreach ($suspiciousIPs as $ip): 
                                $threatLevel = $ip['total_attempts'] > 50 ? 'critical' : 
                                             ($ip['total_attempts'] > 20 ? 'high' : 
                                             ($ip['distinct_accounts'] > 5 ? 'medium' : 'low'));
                            ?>
                            <tr>
                                <td>
                                    <code style="background: #f3f4f6; padding: 5px 10px; border-radius: 5px;">
                                        <?php echo htmlspecialchars($ip['ip_address']); ?>
                                    </code>
                                </td>
                                <td>
                                    <span class="status-badge status-<?php echo $ip['distinct_accounts'] > 5 ? 'critical' : 'medium'; ?>">
                                        <?php echo $ip['distinct_accounts']; ?> حساب
                                    </span>
                                </td>
                                <td>
                                    <strong><?php echo $ip['total_attempts']; ?></strong>
                                </td>
                                <td>
                                    <?php echo date('H:i:s', strtotime($ip['last_attempt'])); ?>
                                </td>
                                <td>
                                    <?php if ($threatLevel == 'critical'): ?>
                                    <span class="status-badge status-critical"><i class="fas fa-skull-crossbones"></i> حرج</span>
                                    <?php elseif ($threatLevel == 'high'): ?>
                                    <span class="status-badge status-high"><i class="fas fa-exclamation-triangle"></i> عالي</span>
                                    <?php elseif ($threatLevel == 'medium'): ?>
                                    <span class="status-badge status-medium"><i class="fas fa-exclamation-circle"></i> متوسط</span>
                                    <?php else: ?>
                                    <span class="status-badge status-low"><i class="fas fa-info-circle"></i> منخفض</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <button class="btn btn-danger btn-sm" onclick="blockIP('<?php echo htmlspecialchars($ip['ip_address']); ?>')">
                                        <i class="fas fa-ban"></i> حظر
                                    </button>
                                    <button class="btn btn-info btn-sm" onclick="viewIPDetails('<?php echo htmlspecialchars($ip['ip_address']); ?>')">
                                        <i class="fas fa-search"></i> تفاصيل
                                    </button>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- قسم أحداث الأمان الأخيرة -->
        <div class="section">
            <div class="section-header">
                <div class="section-title">
                    <i class="fas fa-history"></i>
                    <h3>أحداث الأمان الأخيرة (24 ساعة)</h3>
                </div>
                <div class="section-actions">
                    <button class="btn btn-secondary btn-sm" onclick="openModal('clearLogsModal')">
                        <i class="fas fa-trash-alt"></i> تنظيف السجلات
                    </button>
                </div>
            </div>
            
            <div class="table-responsive">
                <table class="table">
                    <thead>
                        <tr>
                            <th>الوقت</th>
                            <th>المستخدم</th>
                            <th>نوع الحدث</th>
                            <th>الوصف</th>
                            <th>عنوان IP</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recentEvents as $event): 
                            $eventType = strtolower($event['action_type']);
                            $statusClass = strpos($eventType, 'fail') !== false ? 'status-critical' : 
                                          (strpos($eventType, 'block') !== false ? 'status-high' : 
                                          (strpos($eventType, 'warn') !== false ? 'status-medium' : 'status-low'));
                        ?>
                        <tr>
                            <td>
                                <div style="font-size: 0.9rem;">
                                    <div><?php echo date('H:i:s', strtotime($event['created_at'])); ?></div>
                                    <div style="color: var(--gray-color); font-size: 0.8rem;">
                                        <?php echo date('Y-m-d', strtotime($event['created_at'])); ?>
                                    </div>
                                </div>
                            </td>
                            <td>
                                <?php if ($event['email']): ?>
                                <div>
                                    <div><?php echo htmlspecialchars($event['email']); ?></div>
                                    <div style="color: var(--gray-color); font-size: 0.8rem;">
                                        <?php echo $event['role']; ?>
                                    </div>
                                </div>
                                <?php else: ?>
                                <span class="status-badge status-neutral">النظام</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <span class="status-badge <?php echo $statusClass; ?>">
                                    <?php echo htmlspecialchars($event['action_type']); ?>
                                </span>
                            </td>
                            <td>
                                <?php echo htmlspecialchars($event['description']); ?>
                            </td>
                            <td>
                                <code style="font-size: 0.85rem;">
                                    <?php echo htmlspecialchars($event['ip_address']); ?>
                                </code>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- التذييل -->
        <div class="footer">
            <p>نظام إدارة الأمان المتقدم &copy; <?php echo date('Y'); ?> | تم التحديث: <?php echo date('Y-m-d H:i:s'); ?></p>
            <p style="margin-top: 10px; font-size: 0.8rem; color: var(--gray-color);">
                <i class="fas fa-server"></i> الخادم: <?php echo gethostname(); ?> | 
                <i class="fas fa-database"></i> MySQL: <?php echo $pdo->getAttribute(PDO::ATTR_SERVER_VERSION); ?>
            </p>
        </div>
    </div>

    <!-- نافذة حظر IP -->
    <div id="blockIPModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <div class="modal-title"><i class="fas fa-ban"></i> حظر عنوان IP</div>
                <button class="close-modal" onclick="closeModal('blockIPModal')">&times;</button>
            </div>
            <form method="POST" action="">
                <div class="form-group">
                    <label class="form-label">عنوان IP</label>
                    <input type="text" name="ip_address" class="form-control" placeholder="مثال: 192.168.1.100" required>
                </div>
                <div class="form-group">
                    <label class="form-label">سبب الحظر</label>
                    <select name="reason" class="form-control" required>
                        <option value="">اختر السبب...</option>
                        <option value="هجمات متكررة">هجمات متكررة</option>
                        <option value="محاولات اختراق">محاولات اختراق</option>
                        <option value="تصفح غير مصرح">تصفح غير مصرح</option>
                        <option value="نشاط مشبوه">نشاط مشبوه</option>
                        <option value="أسباب إدارية">أسباب إدارية</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">ملاحظات إضافية</label>
                    <textarea name="notes" class="form-control" rows="3" placeholder="ملاحظات إضافية..."></textarea>
                </div>
                <div class="form-actions">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('blockIPModal')">إلغاء</button>
                    <button type="submit" name="block_ip" class="btn btn-danger">تأكيد الحظر</button>
                </div>
            </form>
        </div>
    </div>

    <!-- نافذة تنظيف السجلات -->
    <div id="clearLogsModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <div class="modal-title"><i class="fas fa-trash-alt"></i> تنظيف سجلات الأمان</div>
                <button class="close-modal" onclick="closeModal('clearLogsModal')">&times;</button>
            </div>
            <form method="POST" action="">
                <div class="form-group">
                    <label class="form-label">حذف السجلات الأقدم من</label>
                    <select name="days" class="form-control" required>
                        <option value="7">أسبوع (7 أيام)</option>
                        <option value="30">شهر (30 يوماً)</option>
                        <option value="90">3 أشهر (90 يوماً)</option>
                        <option value="180">6 أشهر (180 يوماً)</option>
                        <option value="365">سنة (365 يوماً)</option>
                    </select>
                </div>
                <div class="alert" style="background: #fff3cd; color: #856404; border-right: 5px solid #ffc107;">
                    <i class="fas fa-exclamation-triangle"></i>
                    <div>
                        <strong>تحذير:</strong> هذا الإجراء لا يمكن التراجع عنه.
                        سيتم حذف جميع سجلات الأمان الأقدم من الفترة المحددة.
                    </div>
                </div>
                <div class="form-actions">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('clearLogsModal')">إلغاء</button>
                    <button type="submit" name="clear_logs" class="btn btn-danger">تأكيد الحذف</button>
                </div>
            </form>
        </div>
    </div>

    <!-- نافذة إرسال تنبيه -->
    <div id="sendAlertModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <div class="modal-title"><i class="fas fa-bell"></i> إرسال تنبيه أمني</div>
                <button class="close-modal" onclick="closeModal('sendAlertModal')">&times;</button>
            </div>
            <form method="POST" action="">
                <div class="form-group">
                    <label class="form-label">البريد الإلكتروني</label>
                    <input type="email" name="email" class="form-control" placeholder="user@example.com" required>
                </div>
                <div class="form-group">
                    <label class="form-label">نوع التنبيه</label>
                    <select name="alert_type" class="form-control" required>
                        <option value="">اختر النوع...</option>
                        <option value="نشاط مشبوه">نشاط مشبوه على حسابك</option>
                        <option value="محاولات دخول">محاولات دخول فاشلة</option>
                        <option value="تغيير إعدادات">تغيير في إعدادات الأمان</option>
                        <option value="تحذير عام">تحذير أمني عام</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">الرسالة</label>
                    <textarea name="message" class="form-control" rows="4" placeholder="أدخل نص الرسالة..." required></textarea>
                </div>
                <div class="form-actions">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('sendAlertModal')">إلغاء</button>
                    <button type="submit" name="send_alert" class="btn btn-warning">إرسال التنبيه</button>
                </div>
            </form>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        // وظائف المخططات
        Chart.defaults.font.family = "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif";
        Chart.defaults.color = '#6b7280';
        
        const loginCtx = document.getElementById('loginActivityChart').getContext('2d');
        const loginChart = new Chart(loginCtx, {
            type: 'line',
            data: {
                labels: <?php echo json_encode(array_column($hourlyData, 'hour')); ?>,
                datasets: [{
                    label: 'محاولات الدخول',
                    data: <?php echo json_encode(array_column($hourlyData, 'attempts')); ?>,
                    borderColor: '#6366f1',
                    backgroundColor: 'rgba(99, 102, 241, 0.1)',
                    borderWidth: 3,
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: '#6366f1',
                    pointRadius: 5,
                    pointHoverRadius: 8
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                        rtl: true,
                        labels: {
                            font: {
                                size: 14
                            }
                        }
                    }
                }
            }
        });
        
        const distributionCtx = document.getElementById('attemptsDistributionChart').getContext('2d');
        const distributionChart = new Chart(distributionCtx, {
            type: 'doughnut',
            data: {
                labels: ['ناجح', 'فاشل', 'مقفل', 'فشل MFA'],
                datasets: [{
                    data: [
                        <?php echo $loginStats['successful']; ?>,
                        <?php echo $loginStats['failed']; ?>,
                        <?php echo $loginStats['locked']; ?>,
                        <?php echo $loginStats['mfa_failed']; ?>
                    ],
                    backgroundColor: [
                        '#10b981',
                        '#ef4444',
                        '#f59e0b',
                        '#8b5cf6'
                    ],
                    borderWidth: 3,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        rtl: true,
                        labels: {
                            font: {
                                size: 13
                            },
                            padding: 20
                        }
                    }
                },
                cutout: '65%'
            }
        });
        
        // وظائف عامة
        function toggleSidebar() {
            const sidebar = document.querySelector('.sidebar');
            sidebar.classList.toggle('active');
        }
        
        function openModal(modalId) {
            document.getElementById(modalId).style.display = 'flex';
        }
        
        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }
        
        window.onclick = function(event) {
            const modals = document.querySelectorAll('.modal');
            modals.forEach(modal => {
                if (event.target === modal) {
                    modal.style.display = 'none';
                }
            });
        };
        
        function refreshDashboard() {
            const refreshBtn = document.querySelector('[onclick="refreshDashboard()"]');
            const originalHTML = refreshBtn.innerHTML;
            
            refreshBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> جاري التحديث...';
            refreshBtn.disabled = true;
            
            setTimeout(() => {
                window.location.reload();
            }, 1000);
        }
        
        function generateReport() {
            alert('جاري إنشاء التقرير...');
        }
        
        function blockIP(ip) {
            if (confirm(`هل أنت متأكد من حظر عنوان IP: ${ip}؟`)) {
                document.querySelector('#blockIPModal input[name="ip_address"]').value = ip;
                openModal('blockIPModal');
            }
        }
        
        function sendAlertToUser(email) {
            document.querySelector('#sendAlertModal input[name="email"]').value = email;
            openModal('sendAlertModal');
        }
        
        // تحديث تلقائي كل 5 دقائق
        setTimeout(() => {
            refreshDashboard();
        }, 300000);
    </script>
</body>
</html>