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

// الحصول على التنبيهات غير المقروءة
$stmt = $pdo->query("
    SELECT * FROM security_alerts 
    WHERE is_read = FALSE 
    ORDER BY created_at DESC
");
$unreadAlerts = $stmt->fetchAll();

// الحصول على جميع التنبيهات
$stmt = $pdo->query("
    SELECT * FROM security_alerts 
    ORDER BY created_at DESC 
    LIMIT 100
");
$allAlerts = $stmt->fetchAll();

// معالجة قراءة التنبيهات
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['mark_as_read'])) {
        $alertId = $_POST['alert_id'];

        $stmt = $pdo->prepare("UPDATE security_alerts SET is_read = TRUE WHERE id = ?");
        $stmt->execute([$alertId]);

        $_SESSION['success_message'] = "تم تعليم التنبيه كمقروء";
        header('Location: alerts.php');
        exit;
    }

    if (isset($_POST['mark_all_read'])) {
        $stmt = $pdo->prepare("UPDATE security_alerts SET is_read = TRUE WHERE is_read = FALSE");
        $stmt->execute();

        $_SESSION['success_message'] = "تم تعليم جميع التنبيهات كمقروءة";
        header('Location: alerts.php');
        exit;
    }

    if (isset($_POST['delete_alert'])) {
        $alertId = $_POST['alert_id'];

        $stmt = $pdo->prepare("DELETE FROM security_alerts WHERE id = ?");
        $stmt->execute([$alertId]);

        $_SESSION['success_message'] = "تم حذف التنبيه بنجاح";
        header('Location: alerts.php');
        exit;
    }

    if (isset($_POST['create_alert'])) {
        $title = $_POST['title'];
        $message = $_POST['message'];
        $priority = $_POST['priority'];
        $recipients = $_POST['recipients'];

        $stmt = $pdo->prepare("
            INSERT INTO security_alerts (title, message, priority, recipients, created_by, created_at) 
            VALUES (?, ?, ?, ?, ?, NOW())
        ");
        $stmt->execute([$title, $message, $priority, $recipients, $user['id']]);

        $auth->logSecurityEvent($user['id'], 'ALERT_CREATED', "تم إنشاء تنبيه: $title");
        $_SESSION['success_message'] = "تم إنشاء التنبيه بنجاح";
        header('Location: alerts.php');
        exit;
    }

    if (isset($_POST['update_alert_settings'])) {
        // تحديث إعدادات التنبيهات
        $settings = $_POST['settings'];

        foreach ($settings as $key => $value) {
            $stmt = $pdo->prepare("
                INSERT INTO alert_settings (setting_key, setting_value, updated_at) 
                VALUES (?, ?, NOW())
                ON DUPLICATE KEY UPDATE setting_value = ?, updated_at = NOW()
            ");
            $stmt->execute([$key, $value, $value]);
        }

        $_SESSION['success_message'] = "تم تحديث إعدادات التنبيهات";
        header('Location: alerts.php');
        exit;
    }
}

// التحقق من الرسائل
$success_message = $_SESSION['success_message'] ?? null;
unset($_SESSION['success_message']);
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>التنبيهات - لوحة التحكم</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="../assets/css/admin.css">

    <style>
        /* ستستخدم نفس الأنماط الأساسية */
        :root {
            --primary-color: #6366f1;
            --primary-dark: #4f46e5;
            --secondary-color: #10b981;
            --danger-color: #ef4444;
            --warning-color: #f59e0b;
            --info-color: #3b82f6;
            --dark-color: #1f2937;
            --light-color: #f9fafb;
            --gray-color: #6b7280;
            --border-radius: 12px;
            --box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
            --transition: all 0.3s ease;
        }

        .alerts-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            flex-wrap: wrap;
            gap: 20px;
        }

        .alerts-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: white;
            border-radius: var(--border-radius);
            padding: 25px;
            text-align: center;
            box-shadow: var(--box-shadow);
            transition: var(--transition);
        }

        .stat-card:hover {
            transform: translateY(-5px);
        }

        .stat-card.critical {
            border-top: 4px solid var(--danger-color);
        }

        .stat-card.warning {
            border-top: 4px solid var(--warning-color);
        }

        .stat-card.info {
            border-top: 4px solid var(--info-color);
        }

        .stat-card.success {
            border-top: 4px solid var(--secondary-color);
        }

        .stat-value {
            font-size: 2.5rem;
            font-weight: 800;
            margin-bottom: 10px;
        }

        .stat-label {
            color: var(--gray-color);
            font-size: 0.95rem;
        }

        .alert-card {
            background: white;
            border-radius: var(--border-radius);
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: var(--box-shadow);
            border-right: 4px solid var(--gray-color);
            transition: var(--transition);
        }

        .alert-card:hover {
            transform: translateX(-5px);
        }

        .alert-card.unread {
            background: linear-gradient(135deg, #fef3c7, #fde68a);
            border-right-color: var(--warning-color);
        }

        .alert-card.critical {
            background: linear-gradient(135deg, #fee2e2, #fecaca);
            border-right-color: var(--danger-color);
        }

        .alert-card.high {
            background: linear-gradient(135deg, #fed7aa, #fdba74);
            border-right-color: #f97316;
        }

        .alert-card.medium {
            background: linear-gradient(135deg, #fef3c7, #fde68a);
            border-right-color: var(--warning-color);
        }

        .alert-card.low {
            background: linear-gradient(135deg, #d1fae5, #a7f3d0);
            border-right-color: var(--secondary-color);
        }

        .alert-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
        }

        .alert-title {
            font-size: 1.2rem;
            font-weight: 700;
            color: var(--dark-color);
        }

        .alert-meta {
            display: flex;
            gap: 15px;
            align-items: center;
        }

        .alert-priority {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }

        .priority-critical {
            background: #fee2e2;
            color: #991b1b;
        }

        .priority-high {
            background: #fed7aa;
            color: #9a3412;
        }

        .priority-medium {
            background: #fef3c7;
            color: #92400e;
        }

        .priority-low {
            background: #d1fae5;
            color: #065f46;
        }

        .alert-time {
            color: var(--gray-color);
            font-size: 0.9rem;
        }

        .alert-message {
            margin-bottom: 15px;
            line-height: 1.6;
            color: var(--dark-color);
        }

        .alert-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 20px;
            padding-top: 15px;
            border-top: 1px solid #f3f4f6;
        }

        .alert-sender {
            color: var(--gray-color);
            font-size: 0.9rem;
        }

        .alert-actions {
            display: flex;
            gap: 10px;
        }

        .btn-sm {
            padding: 8px 16px;
            font-size: 0.85rem;
        }

        .empty-alerts {
            text-align: center;
            padding: 60px 20px;
            color: var(--gray-color);
        }

        .empty-alerts i {
            font-size: 3rem;
            margin-bottom: 20px;
            opacity: 0.5;
        }

        .alerts-tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 10px;
            overflow-x: auto;
        }

        .alerts-tab {
            padding: 12px 24px;
            border: none;
            background: none;
            cursor: pointer;
            font-weight: 600;
            color: var(--gray-color);
            transition: var(--transition);
            white-space: nowrap;
            border-bottom: 3px solid transparent;
        }

        .alerts-tab.active {
            color: var(--primary-color);
            border-bottom-color: var(--primary-color);
        }

        .alerts-tab:hover:not(.active) {
            color: var(--dark-color);
        }

        .alerts-section {
            display: none;
        }

        .alerts-section.active {
            display: block;
            animation: fadeIn 0.5s ease;
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .notification-bell {
            position: relative;
            cursor: pointer;
        }

        .notification-badge {
            position: absolute;
            top: -8px;
            left: -8px;
            background: var(--danger-color);
            color: white;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
            font-weight: bold;
        }

        @media (max-width: 768px) {
            .alerts-header {
                flex-direction: column;
                align-items: stretch;
            }

            .alerts-stats {
                grid-template-columns: repeat(2, 1fr);
            }

            .alert-header {
                flex-direction: column;
                gap: 10px;
            }

            .alert-meta {
                width: 100%;
                justify-content: space-between;
            }

            .alert-footer {
                flex-direction: column;
                gap: 15px;
                align-items: stretch;
            }

            .alert-actions {
                justify-content: flex-end;
            }
        }
    </style>
</head>

<body>
    <?php include 'components/sidebar.php'; ?>

    <div class="main-content">
        <div class="top-bar">
            <div class="page-title">
                <h2><i class="fas fa-bell"></i> التنبيهات والإشعارات</h2>
                <p>إدارة وإرسال التنبيهات الأمنية</p>
            </div>

            <div class="quick-actions">
                <button class="action-btn primary" onclick="openModal('createAlertModal')">
                    <i class="fas fa-plus"></i> إنشاء تنبيه
                </button>
                <?php if (count($unreadAlerts) > 0): ?>
                    <form method="POST" action="" style="display: inline;">
                        <button type="submit" name="mark_all_read" class="action-btn">
                            <i class="fas fa-check-double"></i> تعليم الكل كمقروء
                        </button>
                    </form>
                <?php endif; ?>
                <div class="notification-bell" onclick="showNotifications()">
                    <i class="fas fa-bell fa-2x" style="color: var(--warning-color);"></i>
                    <?php if (count($unreadAlerts) > 0): ?>
                        <div class="notification-badge"><?php echo count($unreadAlerts); ?></div>
                    <?php endif; ?>
                </div>
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

        <!-- إحصائيات التنبيهات -->
        <div class="alerts-stats">
            <?php
            // حساب إحصائيات التنبيهات
            $criticalCount = 0;
            $highCount = 0;
            $mediumCount = 0;
            $lowCount = 0;

            foreach ($allAlerts as $alert) {
                switch ($alert['priority']) {
                    case 'critical':
                        $criticalCount++;
                        break;
                    case 'high':
                        $highCount++;
                        break;
                    case 'medium':
                        $mediumCount++;
                        break;
                    case 'low':
                        $lowCount++;
                        break;
                }
            }
            ?>
            <div class="stat-card critical">
                <div class="stat-value"><?php echo $criticalCount; ?></div>
                <div class="stat-label">تنبيهات حرجة</div>
            </div>
            <div class="stat-card warning">
                <div class="stat-value"><?php echo $highCount; ?></div>
                <div class="stat-label">تنبيهات عالية</div>
            </div>
            <div class="stat-card info">
                <div class="stat-value"><?php echo $mediumCount; ?></div>
                <div class="stat-label">تنبيهات متوسطة</div>
            </div>
            <div class="stat-card success">
                <div class="stat-value"><?php echo count($unreadAlerts); ?></div>
                <div class="stat-label">غير مقروء</div>
            </div>
        </div>

        <!-- تبويبات التنبيهات -->
        <div class="alerts-tabs">
            <button class="alerts-tab active" onclick="showAlertsSection('unread')">
                <i class="fas fa-envelope"></i> غير مقروء (<?php echo count($unreadAlerts); ?>)
            </button>
            <button class="alerts-tab" onclick="showAlertsSection('all')">
                <i class="fas fa-list"></i> جميع التنبيهات
            </button>
            <button class="alerts-tab" onclick="showAlertsSection('settings')">
                <i class="fas fa-cog"></i> إعدادات التنبيهات
            </button>
            <button class="alerts-tab" onclick="showAlertsSection('templates')">
                <i class="fas fa-file-alt"></i> قوالب التنبيهات
            </button>
        </div>

        <!-- التنبيهات غير المقروءة -->
        <div class="alerts-section active" id="unread-section">
            <div class="section-header" style="margin-bottom: 25px;">
                <div class="section-title">
                    <i class="fas fa-envelope"></i>
                    <h3>التنبيهات غير المقروءة</h3>
                </div>
            </div>

            <?php if (empty($unreadAlerts)): ?>
                <div class="empty-alerts">
                    <i class="fas fa-check-circle"></i>
                    <h3>لا توجد تنبيهات غير مقروءة</h3>
                    <p>جميع التنبيهات تمت قراءتها.</p>
                </div>
            <?php else: ?>
                <?php foreach ($unreadAlerts as $alert): ?>
                    <div class="alert-card unread <?php echo $alert['priority']; ?>">
                        <div class="alert-header">
                            <div class="alert-title"><?php echo htmlspecialchars($alert['title']); ?></div>
                            <div class="alert-meta">
                                <span class="alert-priority priority-<?php echo $alert['priority']; ?>">
                                    <?php
                                    $priorityNames = [
                                        'critical' => 'حرج',
                                        'high' => 'عالي',
                                        'medium' => 'متوسط',
                                        'low' => 'منخفض'
                                    ];
                                    echo $priorityNames[$alert['priority']] ?? $alert['priority'];
                                    ?>
                                </span>
                                <span class="alert-time">
                                    <?php echo date('Y-m-d H:i', strtotime($alert['created_at'])); ?>
                                </span>
                            </div>
                        </div>

                        <div class="alert-message">
                            <?php echo nl2br(htmlspecialchars($alert['message'])); ?>
                        </div>

                        <div class="alert-footer">
                            <div class="alert-sender">
                                <i class="fas fa-user-shield"></i>
                                <?php
                                if ($alert['created_by']) {
                                    $stmt = $pdo->prepare("SELECT email FROM users WHERE id = ?");
                                    $stmt->execute([$alert['created_by']]);
                                    $creator = $stmt->fetch();
                                    echo 'بواسطة: ' . ($creator ? htmlspecialchars($creator['email']) : 'النظام');
                                } else {
                                    echo 'النظام';
                                }
                                ?>
                            </div>

                            <div class="alert-actions">
                                <form method="POST" action="" style="display: inline;">
                                    <input type="hidden" name="alert_id" value="<?php echo $alert['id']; ?>">
                                    <button type="submit" name="mark_as_read" class="btn btn-sm btn-primary">
                                        <i class="fas fa-check"></i> تعليم كمقروء
                                    </button>
                                </form>
                                <button class="btn btn-sm btn-secondary" onclick="viewAlertDetails(<?php echo $alert['id']; ?>)">
                                    <i class="fas fa-eye"></i> عرض
                                </button>
                                <button class="btn btn-sm btn-info" onclick="forwardAlert(<?php echo $alert['id']; ?>)">
                                    <i class="fas fa-share"></i> تحويل
                                </button>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <!-- جميع التنبيهات -->
        <div class="alerts-section" id="all-section">
            <div class="section-header" style="margin-bottom: 25px;">
                <div class="section-title">
                    <i class="fas fa-list"></i>
                    <h3>جميع التنبيهات</h3>
                </div>
                <div style="color: var(--gray-color); font-size: 0.9rem;">
                    <?php echo count($allAlerts); ?> تنبيه
                </div>
            </div>

            <?php if (empty($allAlerts)): ?>
                <div class="empty-alerts">
                    <i class="fas fa-bell-slash"></i>
                    <h3>لا توجد تنبيهات</h3>
                    <p>لم يتم إنشاء أي تنبيهات بعد.</p>
                </div>
            <?php else: ?>
                <?php foreach ($allAlerts as $alert): ?>
                    <div class="alert-card <?php echo $alert['priority']; ?> <?php echo $alert['is_read'] ? '' : 'unread'; ?>">
                        <div class="alert-header">
                            <div class="alert-title">
                                <?php echo htmlspecialchars($alert['title']); ?>
                                <?php if (!$alert['is_read']): ?>
                                    <span style="background: var(--danger-color); color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; margin-right: 10px;">جديد</span>
                                <?php endif; ?>
                            </div>
                            <div class="alert-meta">
                                <span class="alert-priority priority-<?php echo $alert['priority']; ?>">
                                    <?php
                                    $priorityNames = [
                                        'critical' => 'حرج',
                                        'high' => 'عالي',
                                        'medium' => 'متوسط',
                                        'low' => 'منخفض'
                                    ];
                                    echo $priorityNames[$alert['priority']] ?? $alert['priority'];
                                    ?>
                                </span>
                                <span class="alert-time">
                                    <?php echo date('Y-m-d H:i', strtotime($alert['created_at'])); ?>
                                </span>
                            </div>
                        </div>

                        <div class="alert-message">
                            <?php echo nl2br(htmlspecialchars($alert['message'])); ?>
                        </div>

                        <div class="alert-footer">
                            <div class="alert-sender">
                                <i class="fas fa-user-shield"></i>
                                <?php
                                if ($alert['created_by']) {
                                    $stmt = $pdo->prepare("SELECT email FROM users WHERE id = ?");
                                    $stmt->execute([$alert['created_by']]);
                                    $creator = $stmt->fetch();
                                    echo 'بواسطة: ' . ($creator ? htmlspecialchars($creator['email']) : 'النظام');
                                } else {
                                    echo 'النظام';
                                }
                                ?>
                            </div>

                            <div class="alert-actions">
                                <?php if (!$alert['is_read']): ?>
                                    <form method="POST" action="" style="display: inline;">
                                        <input type="hidden" name="alert_id" value="<?php echo $alert['id']; ?>">
                                        <button type="submit" name="mark_as_read" class="btn btn-sm btn-primary">
                                            <i class="fas fa-check"></i> مقروء
                                        </button>
                                    </form>
                                <?php endif; ?>
                                <button class="btn btn-sm btn-secondary" onclick="viewAlertDetails(<?php echo $alert['id']; ?>)">
                                    <i class="fas fa-eye"></i> عرض
                                </button>
                                <button class="btn btn-sm btn-warning" onclick="editAlert(<?php echo $alert['id']; ?>)">
                                    <i class="fas fa-edit"></i> تعديل
                                </button>
                                <form method="POST" action="" style="display: inline;" onsubmit="return confirm('هل تريد حذف هذا التنبيه؟')">
                                    <input type="hidden" name="alert_id" value="<?php echo $alert['id']; ?>">
                                    <button type="submit" name="delete_alert" class="btn btn-sm btn-danger">
                                        <i class="fas fa-trash-alt"></i> حذف
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <!-- إعدادات التنبيهات -->
        <div class="alerts-section" id="settings-section">
            <div class="section">
                <div class="section-header">
                    <div class="section-title">
                        <i class="fas fa-cog"></i>
                        <h3>إعدادات التنبيهات</h3>
                    </div>
                </div>

                <form method="POST" action="">
                    <div style="margin-bottom: 30px;">
                        <h4 style="margin-bottom: 15px; color: var(--dark-color);">
                            <i class="fas fa-bell"></i> إعدادات الإشعارات
                        </h4>
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
                            <div>
                                <label class="checkbox-label">
                                    <input type="checkbox" name="settings[email_notifications]" value="1" checked>
                                    <span class="checkbox-text">إشعارات البريد الإلكتروني</span>
                                </label>
                                <p class="checkbox-description">
                                    إرسال تنبيهات عبر البريد الإلكتروني للتنبيهات المهمة
                                </p>
                            </div>

                            <div>
                                <label class="checkbox-label">
                                    <input type="checkbox" name="settings[browser_notifications]" value="1" checked>
                                    <span class="checkbox-text">إشعارات المتصفح</span>
                                </label>
                                <p class="checkbox-description">
                                    عرض إشعارات في المتصفح للتنبيهات المهمة
                                </p>
                            </div>

                            <div>
                                <label class="checkbox-label">
                                    <input type="checkbox" name="settings[sms_notifications]" value="1">
                                    <span class="checkbox-text">إشعارات SMS</span>
                                </label>
                                <p class="checkbox-description">
                                    إرسال رسائل SMS للتنبيهات الحرجة (يتطلب تكوين بوابة SMS)
                                </p>
                            </div>
                        </div>
                    </div>

                    <div style="margin-bottom: 30px;">
                        <h4 style="margin-bottom: 15px; color: var(--dark-color);">
                            <i class="fas fa-sliders-h"></i> عتبات التنبيهات
                        </h4>
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px;">
                            <div>
                                <label class="form-label">محاولات دخول فاشلة</label>
                                <input type="number" name="settings[failed_login_threshold]" class="form-control"
                                    value="5" min="1" max="20">
                                <small style="color: var(--gray-color);">عدد المحاولات الفاشلة قبل إنشاء تنبيه</small>
                            </div>

                            <div>
                                <label class="form-label">سجلات أمان/ساعة</label>
                                <input type="number" name="settings[logs_per_hour_threshold]" class="form-control"
                                    value="100" min="10" max="1000">
                                <small style="color: var(--gray-color);">عدد السجلات في الساعة قبل إنشاء تنبيه</small>
                            </div>

                            <div>
                                <label class="form-label">مستخدمين مقفلين</label>
                                <input type="number" name="settings[locked_users_threshold]" class="form-control"
                                    value="3" min="1" max="20">
                                <small style="color: var(--gray-color);">عدد المستخدمين المقفلين قبل إنشاء تنبيه</small>
                            </div>
                        </div>
                    </div>

                    <div style="margin-bottom: 30px;">
                        <h4 style="margin-bottom: 15px; color: var(--dark-color);">
                            <i class="fas fa-users"></i> المستلمين الافتراضيين
                        </h4>
                        <div>
                            <label class="form-label">البريد الإلكتروني للمستلمين</label>
                            <input type="text" name="settings[default_recipients]" class="form-control"
                                placeholder="admin@example.com, security@example.com">
                            <small style="color: var(--gray-color);">يفصل بين العناوين بفواصل</small>
                        </div>
                    </div>

                    <div class="actions-bar">
                        <button type="submit" name="update_alert_settings" class="btn-save">
                            <i class="fas fa-save"></i> حفظ الإعدادات
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- قوالب التنبيهات -->
        <div class="alerts-section" id="templates-section">
            <div class="section">
                <div class="section-header">
                    <div class="section-title">
                        <i class="fas fa-file-alt"></i>
                        <h3>قوالب التنبيهات</h3>
                    </div>
                    <button class="btn btn-primary" onclick="createNewTemplate()">
                        <i class="fas fa-plus"></i> قالب جديد
                    </button>
                </div>

                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 25px;">
                    <!-- قالب تنبيهات الدخول الفاشل -->
                    <div class="template-card" style="background: white; border-radius: var(--border-radius); padding: 25px; box-shadow: var(--box-shadow);">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                            <h4 style="color: var(--dark-color);">تنبيه دخول فاشل</h4>
                            <span class="status-badge status-high">حرج</span>
                        </div>
                        <p style="color: var(--gray-color); margin-bottom: 15px; line-height: 1.5;">
                            إشعار عند فشل محاولات دخول متعددة لحساب معين
                        </p>
                        <div style="background: #f9fafb; padding: 15px; border-radius: 8px; margin-bottom: 15px;">
                            <strong>العنوان:</strong> فشل محاولات دخول متعددة<br>
                            <strong>المستلمون:</strong> المسؤولون والمستخدم المعني
                        </div>
                        <div style="display: flex; gap: 10px;">
                            <button class="btn btn-sm btn-primary" onclick="useTemplate('login_failure')">
                                <i class="fas fa-check"></i> استخدام
                            </button>
                            <button class="btn btn-sm btn-secondary" onclick="editTemplate('login_failure')">
                                <i class="fas fa-edit"></i> تعديل
                            </button>
                        </div>
                    </div>

                    <!-- قالب تنبيهات الحساب المقفل -->
                    <div class="template-card" style="background: white; border-radius: var(--border-radius); padding: 25px; box-shadow: var(--box-shadow);">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                            <h4 style="color: var(--dark-color);">تنبيه حساب مقفل</h4>
                            <span class="status-badge status-medium">متوسط</span>
                        </div>
                        <p style="color: var(--gray-color); margin-bottom: 15px; line-height: 1.5;">
                            إشعار عند قفل حساب بسبب محاولات دخول فاشلة متعددة
                        </p>
                        <div style="background: #f9fafb; padding: 15px; border-radius: 8px; margin-bottom: 15px;">
                            <strong>العنوان:</strong> تم قفل حسابك<br>
                            <strong>المستلمون:</strong> المستخدم المعني
                        </div>
                        <div style="display: flex; gap: 10px;">
                            <button class="btn btn-sm btn-primary" onclick="useTemplate('account_locked')">
                                <i class="fas fa-check"></i> استخدام
                            </button>
                            <button class="btn btn-sm btn-secondary" onclick="editTemplate('account_locked')">
                                <i class="fas fa-edit"></i> تعديل
                            </button>
                        </div>
                    </div>

                    <!-- قالب تنبيهات IP محظور -->
                    <div class="template-card" style="background: white; border-radius: var(--border-radius); padding: 25px; box-shadow: var(--box-shadow);">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                            <h4 style="color: var(--dark-color);">تنبيه IP محظور</h4>
                            <span class="status-badge status-critical">حرج</span>
                        </div>
                        <p style="color: var(--gray-color); margin-bottom: 15px; line-height: 1.5;">
                            إشعار عند حظر عنوان IP بسبب نشاط مشبوه
                        </p>
                        <div style="background: #f9fafb; padding: 15px; border-radius: 8px; margin-bottom: 15px;">
                            <strong>العنوان:</strong> تم حظر عنوان IP<br>
                            <strong>المستلمون:</strong> المسؤولون فقط
                        </div>
                        <div style="display: flex; gap: 10px;">
                            <button class="btn btn-sm btn-primary" onclick="useTemplate('ip_blocked')">
                                <i class="fas fa-check"></i> استخدام
                            </button>
                            <button class="btn btn-sm btn-secondary" onclick="editTemplate('ip_blocked')">
                                <i class="fas fa-edit"></i> تعديل
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- نافذة إنشاء تنبيه -->
    <div id="createAlertModal" class="modal">
        <div class="modal-content" style="max-width: 600px;">
            <div class="modal-header">
                <div class="modal-title"><i class="fas fa-plus"></i> إنشاء تنبيه جديد</div>
                <button class="close-modal" onclick="closeModal('createAlertModal')">&times;</button>
            </div>
            <form method="POST" action="">
                <div style="padding: 20px;">
                    <div class="form-group">
                        <label class="form-label">عنوان التنبيه *</label>
                        <input type="text" name="title" class="form-control" required
                            placeholder="مثال: نشاط مشبوه على حساب مستخدم">
                    </div>

                    <div class="form-group">
                        <label class="form-label">الرسالة *</label>
                        <textarea name="message" class="form-control" rows="6" required
                            placeholder="أدخل نص التنبيه..."></textarea>
                        <small style="color: var(--gray-color);">يمكنك استخدام HTML بسيط في النص</small>
                    </div>

                    <div class="form-group">
                        <label class="form-label">الأولوية *</label>
                        <select name="priority" class="form-control" required>
                            <option value="low">منخفض (معلومات)</option>
                            <option value="medium">متوسط (تحذير)</option>
                            <option value="high">عالي (مهم)</option>
                            <option value="critical">حرج (عاجل)</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label class="form-label">المستلمون</label>
                        <select name="recipients" class="form-control">
                            <option value="all_admins">جميع المسؤولين</option>
                            <option value="all_users">جميع المستخدمين</option>
                            <option value="specific">محددين يدوياً</option>
                        </select>
                    </div>

                    <div class="form-group" id="specificRecipients" style="display: none;">
                        <label class="form-label">العناوين المحددة</label>
                        <input type="text" class="form-control"
                            placeholder="أدخل العناوين مفصولة بفواصل">
                    </div>

                    <div class="form-group">
                        <label class="checkbox-label">
                            <input type="checkbox" name="send_email" checked>
                            <span class="checkbox-text">إرسال بريد إلكتروني</span>
                        </label>
                    </div>

                    <div style="text-align: center; margin-top: 25px;">
                        <button type="button" class="btn btn-secondary" onclick="closeModal('createAlertModal')">إلغاء</button>
                        <button type="submit" name="create_alert" class="btn btn-primary">إنشاء التنبيه</button>
                    </div>
                </div>
            </form>
        </div>
    </div>

    <!-- نافذة الإشعارات السريعة -->
    <div id="notificationsModal" class="modal">
        <div class="modal-content" style="max-width: 500px;">
            <div class="modal-header">
                <div class="modal-title"><i class="fas fa-bell"></i> الإشعارات الحديثة</div>
                <button class="close-modal" onclick="closeModal('notificationsModal')">&times;</button>
            </div>
            <div style="padding: 20px; max-height: 400px; overflow-y: auto;">
                <?php foreach ($unreadAlerts as $alert): ?>
                    <div style="padding: 15px; margin-bottom: 10px; background: #f9fafb; border-radius: 8px; border-right: 3px solid var(--warning-color);">
                        <div style="font-weight: 600; margin-bottom: 5px;"><?php echo htmlspecialchars($alert['title']); ?></div>
                        <div style="color: var(--gray-color); font-size: 0.9rem;">
                            <?php echo date('H:i', strtotime($alert['created_at'])); ?>
                        </div>
                    </div>
                <?php endforeach; ?>

                <?php if (empty($unreadAlerts)): ?>
                    <div style="text-align: center; padding: 40px; color: var(--gray-color);">
                        <i class="fas fa-bell-slash fa-2x"></i>
                        <p style="margin-top: 15px;">لا توجد إشعارات جديدة</p>
                    </div>
                <?php endif; ?>
            </div>
            <div style="padding: 20px; border-top: 1px solid #e5e7eb; text-align: center;">
                <a href="alerts.php" class="btn btn-primary">عرض جميع التنبيهات</a>
            </div>
        </div>
    </div>

    <script>
        // إظهار وإخفاء أقسام التنبيهات
        function showAlertsSection(sectionId) {
            // إخفاء جميع الأقسام
            document.querySelectorAll('.alerts-section').forEach(section => {
                section.classList.remove('active');
            });

            // إزالة التفعيل من جميع التبويبات
            document.querySelectorAll('.alerts-tab').forEach(tab => {
                tab.classList.remove('active');
            });

            // إظهار القسم المطلوب
            document.getElementById(sectionId + '-section').classList.add('active');

            // تفعيل التبويب المطلوب
            document.querySelector(`.alerts-tab[onclick="showAlertsSection('${sectionId}')"]`).classList.add('active');
        }

        // فتح وإغلاق النماذج
        function openModal(modalId) {
            document.getElementById(modalId).style.display = 'flex';
        }

        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }

        // عرض الإشعارات السريعة
        function showNotifications() {
            openModal('notificationsModal');
        }

        // عرض تفاصيل التنبيه
        function viewAlertDetails(alertId) {
            // في الواقع، ستقوم بجلب البيانات عبر AJAX
            const modalContent = `
                <div class="modal" id="alertDetailsModal" style="display: flex;">
                    <div class="modal-content" style="max-width: 700px;">
                        <div class="modal-header">
                            <div class="modal-title"><i class="fas fa-file-alt"></i> تفاصيل التنبيه</div>
                            <button class="close-modal" onclick="closeModal('alertDetailsModal')">&times;</button>
                        </div>
                        <div style="padding: 20px;">
                            <div class="alert-card critical">
                                <div class="alert-header">
                                    <div class="alert-title">نشاط مشبوه على حساب مستخدم</div>
                                    <div class="alert-meta">
                                        <span class="alert-priority priority-critical">حرج</span>
                                        <span class="alert-time">2024-01-15 14:30:45</span>
                                    </div>
                                </div>
                                
                                <div class="alert-message">
                                    تم اكتشاف نشاط مشبوه على حساب المستخدم user@example.com.<br><br>
                                    التفاصيل:<br>
                                    - 15 محاولة دخول فاشلة خلال 30 دقيقة<br>
                                    - من 3 عناوين IP مختلفة<br>
                                    - تم حظر الحساب تلقائياً<br>
                                    - آخر محاولة: 14:30:45 من IP 192.168.1.100
                                </div>
                                
                                <div class="alert-footer">
                                    <div class="alert-sender">
                                        <i class="fas fa-user-shield"></i>
                                        بواسطة: النظام
                                    </div>
                                    
                                    <div style="margin-top: 20px; padding: 15px; background: #f9fafb; border-radius: 8px;">
                                        <h4 style="margin-bottom: 10px; color: var(--dark-color);">المستلمون:</h4>
                                        <p>admin@example.com, security@example.com, user@example.com</p>
                                    </div>
                                    
                                    <div style="margin-top: 20px; padding: 15px; background: #fef3c7; border-radius: 8px;">
                                        <h4 style="margin-bottom: 10px; color: #92400e;"><i class="fas fa-lightbulb"></i> الإجراءات المقترحة:</h4>
                                        <ul style="margin-right: 20px;">
                                            <li>التحقق من هوية المستخدم</li>
                                            <li>مراجعة سجلات الدخول</li>
                                            <li>التحقق من أجهزة المستخدم</li>
                                            <li>إعادة تعيين كلمة المرور إذا لزم الأمر</li>
                                        </ul>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div style="padding: 20px; border-top: 1px solid #e5e7eb; text-align: center;">
                            <button class="btn btn-primary" onclick="closeModal('alertDetailsModal')">
                                <i class="fas fa-times"></i> إغلاق
                            </button>
                        </div>
                    </div>
                </div>
            `;

            document.body.insertAdjacentHTML('beforeend', modalContent);
        }

        // تحويل التنبيه
        function forwardAlert(alertId) {
            const recipients = prompt('أدخل عناوين البريد الإلكتروني للمستلمين الجدد (مفصولة بفواصل):');
            if (recipients) {
                alert(`تم تحويل التنبيه #${alertId} إلى: ${recipients}`);
                // في الواقع، ستقوم بإرسال الطلب إلى الخادم
            }
        }

        // تعديل التنبيه
        function editAlert(alertId) {
            alert(`جاري تحميل التنبيه #${alertId} للتعديل...`);
            // في الواقع، ستقوم بتحميل بيانات التنبيه وعرضها في نموذج التعديل
        }

        // استخدام قالب
        function useTemplate(templateId) {
            document.querySelector('input[name="title"]').value = 'تنبيه قياسي';
            document.querySelector('textarea[name="message"]').value = 'هذا تنبيف قياسي تم إنشاؤه من القالب.';
            closeModal('createAlertModal');
            openModal('createAlertModal');
        }

        // تعديل قالب
        function editTemplate(templateId) {
            alert(`تعديل القالب: ${templateId}`);
        }

        // إنشاء قالب جديد
        function createNewTemplate() {
            const modalContent = `
                <div class="modal" id="newTemplateModal" style="display: flex;">
                    <div class="modal-content" style="max-width: 600px;">
                        <div class="modal-header">
                            <div class="modal-title"><i class="fas fa-file-alt"></i> إنشاء قالب جديد</div>
                            <button class="close-modal" onclick="closeModal('newTemplateModal')">&times;</button>
                        </div>
                        <div style="padding: 20px;">
                            <div class="form-group">
                                <label class="form-label">اسم القالب *</label>
                                <input type="text" class="form-control" placeholder="مثال: تنبيه دخول فاشل">
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label">العنوان *</label>
                                <input type="text" class="form-control" placeholder="{{user}} - فشل محاولات دخول">
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label">نص القالب *</label>
                                <textarea class="form-control" rows="8" placeholder="أدخل نص القالب..."></textarea>
                                <small style="color: var(--gray-color);">المتغيرات المتاحة: {{user}}, {{ip}}, {{count}}, {{time}}</small>
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label">الأولوية</label>
                                <select class="form-control">
                                    <option value="low">منخفض</option>
                                    <option value="medium">متوسط</option>
                                    <option value="high">عالي</option>
                                    <option value="critical">حرج</option>
                                </select>
                            </div>
                            
                            <div style="text-align: center; margin-top: 25px;">
                                <button type="button" class="btn btn-secondary" onclick="closeModal('newTemplateModal')">إلغاء</button>
                                <button type="button" class="btn btn-primary" onclick="saveTemplate()">حفظ القالب</button>
                            </div>
                        </div>
                    </div>
                </div>
            `;

            document.body.insertAdjacentHTML('beforeend', modalContent);
        }

        function saveTemplate() {
            alert('تم حفظ القالب بنجاح');
            closeModal('newTemplateModal');
        }

        // تغيير عرض حقل المستلمين المحددين
        document.addEventListener('DOMContentLoaded', function() {
            const recipientsSelect = document.querySelector('select[name="recipients"]');
            if (recipientsSelect) {
                recipientsSelect.addEventListener('change', function() {
                    const specificField = document.getElementById('specificRecipients');
                    specificField.style.display = this.value === 'specific' ? 'block' : 'none';
                });
            }
        });

        // إغلاق النماذج عند النقر خارجها
        window.onclick = function(event) {
            const modals = document.querySelectorAll('.modal');
            modals.forEach(modal => {
                if (event.target === modal) {
                    modal.style.display = 'none';
                }
            });
        };

        // تحديث عدد التنبيهات غير المقروءة تلقائياً
        function updateUnreadCount() {
            fetch('get-unread-count.php')
                .then(response => response.json())
                .then(data => {
                    if (data.count > 0) {
                        const badge = document.querySelector('.notification-badge') ||
                            document.createElement('div');
                        badge.className = 'notification-badge';
                        badge.textContent = data.count;

                        const bell = document.querySelector('.notification-bell');
                        if (!bell.querySelector('.notification-badge')) {
                            bell.appendChild(badge);
                        } else {
                            bell.querySelector('.notification-badge').textContent = data.count;
                        }
                    } else {
                        const badge = document.querySelector('.notification-badge');
                        if (badge) badge.remove();
                    }
                })
                .catch(error => console.error('Error:', error));
        }

        // تحديث كل دقيقة
        setInterval(updateUnreadCount, 60000);

        // إشعارات المتصفح
        if ('Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission().then(permission => {
                if (permission === 'granted') {
                    console.log('تم تفعيل إشعارات المتصفح');
                }
            });
        }

        // محاكاة إشعارات جديدة (للاختبار)
        setTimeout(() => {
            // new Notification('نظام الأمان', {
            //     body: 'تنبيه جديد: نشاط مشبوه تم اكتشافه',
            //     icon: '/favicon.ico'
            // });
        }, 10000);
    </script>
</body>

</html>