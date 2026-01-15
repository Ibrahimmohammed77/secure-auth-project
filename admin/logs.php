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

// عوامل التصفية
$logType = $_GET['type'] ?? '';
$severity = $_GET['severity'] ?? '';
$startDate = $_GET['start_date'] ?? date('Y-m-d', strtotime('-7 days'));
$endDate = $_GET['end_date'] ?? date('Y-m-d');
$search = $_GET['search'] ?? '';
$userId = $_GET['user_id'] ?? '';

// بناء الاستعلام
$query = "
    SELECT 
        sl.*, 
        u.email as user_email,
        u.role as user_role,
        DATE_FORMAT(sl.created_at, '%Y-%m-%d %H:%i:%s') as log_time
    FROM security_logs sl
    LEFT JOIN users u ON sl.user_id = u.id
    WHERE 1=1
";

$params = [];

if (!empty($logType)) {
    $query .= " AND sl.action_type = :log_type";
    $params[':log_type'] = $logType;
}

if (!empty($severity)) {
    if ($severity === 'high') {
        $query .= " AND (sl.action_type LIKE '%FAIL%' OR sl.action_type LIKE '%BLOCK%' OR sl.action_type LIKE '%LOCK%')";
    } elseif ($severity === 'medium') {
        $query .= " AND (sl.action_type LIKE '%WARN%' OR sl.action_type LIKE '%ATTEMPT%')";
    } elseif ($severity === 'low') {
        $query .= " AND (sl.action_type LIKE '%SUCCESS%' OR sl.action_type LIKE '%LOGIN%')";
    }
}

if (!empty($startDate)) {
    $query .= " AND DATE(sl.created_at) >= :start_date";
    $params[':start_date'] = $startDate;
}

if (!empty($endDate)) {
    $query .= " AND DATE(sl.created_at) <= :end_date";
    $params[':end_date'] = $endDate;
}

if (!empty($search)) {
    $query .= " AND (sl.description LIKE :search OR sl.ip_address LIKE :search OR u.email LIKE :search)";
    $params[':search'] = "%$search%";
}

if (!empty($userId) && $userId !== 'all') {
    $query .= " AND sl.user_id = :user_id";
    $params[':user_id'] = $userId;
}

$query .= " ORDER BY sl.created_at DESC LIMIT 500";

$stmt = $pdo->prepare($query);
$stmt->execute($params);
$logs = $stmt->fetchAll();

// الحصول على أنواع السجلات المختلفة
$stmt = $pdo->query("SELECT DISTINCT action_type FROM security_logs ORDER BY action_type");
$logTypes = $stmt->fetchAll(PDO::FETCH_COLUMN);

// الحصول على قائمة المستخدمين للسجلات
$stmt = $pdo->query("SELECT DISTINCT u.id, u.email FROM security_logs sl JOIN users u ON sl.user_id = u.id ORDER BY u.email");
$usersWithLogs = $stmt->fetchAll();

// إحصائيات السجلات
$statsQuery = "
    SELECT 
        COUNT(*) as total_logs,
        SUM(CASE WHEN action_type LIKE '%FAIL%' OR action_type LIKE '%BLOCK%' THEN 1 ELSE 0 END) as critical_logs,
        SUM(CASE WHEN action_type LIKE '%WARN%' THEN 1 ELSE 0 END) as warning_logs,
        SUM(CASE WHEN action_type LIKE '%SUCCESS%' THEN 1 ELSE 0 END) as success_logs,
        DATE(created_at) as log_date
    FROM security_logs 
    WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    GROUP BY DATE(created_at)
    ORDER BY log_date
";
$stmt = $pdo->query($statsQuery);
$logStats = $stmt->fetchAll();

// معالجة تصدير السجلات
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['export_logs'])) {
    $format = $_POST['format'];
    
    if ($format === 'csv') {
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename=security_logs_' . date('Y-m-d') . '.csv');
        
        $output = fopen('php://output', 'w');
        fputcsv($output, ['التاريخ', 'الوقت', 'نوع الحدث', 'المستخدم', 'الدور', 'الوصف', 'عنوان IP', 'معلومات المتصفح']);
        
        foreach ($logs as $log) {
            fputcsv($output, [
                date('Y-m-d', strtotime($log['created_at'])),
                date('H:i:s', strtotime($log['created_at'])),
                $log['action_type'],
                $log['user_email'] ?? 'النظام',
                $log['user_role'] ?? 'N/A',
                $log['description'],
                $log['ip_address'],
                substr($log['user_agent'] ?? '', 0, 100)
            ]);
        }
        
        fclose($output);
        exit;
    }
}

// معالجة حذف السجلات القديمة
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_old_logs'])) {
    $days = intval($_POST['delete_days']);
    if ($days > 0) {
        $stmt = $pdo->prepare("DELETE FROM security_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)");
        $stmt->execute([$days]);
        
        $auth->logSecurityEvent($user['id'], 'LOGS_CLEANED', "تم حذف سجلات أقدم من $days أيام");
        $_SESSION['success_message'] = "تم حذف السجلات الأقدم من $days أيام بنجاح";
        header('Location: logs.php');
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
    <title>سجلات النظام - لوحة التحكم</title>
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

        .logs-filters {
            background: white;
            border-radius: var(--border-radius);
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: var(--box-shadow);
        }

        .filters-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        .filter-group {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .filter-label {
            font-weight: 600;
            color: var(--dark-color);
        }

        .filter-control {
            padding: 10px 14px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            font-size: 1rem;
            transition: var(--transition);
        }

        .filter-control:focus {
            outline: none;
            border-color: var(--primary-color);
        }

        .filter-actions {
            display: flex;
            gap: 15px;
            margin-top: 20px;
            flex-wrap: wrap;
        }

        .log-entry {
            background: white;
            border-radius: var(--border-radius);
            padding: 20px;
            margin-bottom: 15px;
            box-shadow: var(--box-shadow);
            border-right: 4px solid var(--gray-color);
            transition: var(--transition);
        }

        .log-entry:hover {
            transform: translateX(-5px);
        }

        .log-entry.critical {
            border-right-color: var(--danger-color);
            background: linear-gradient(135deg, #fee2e2, #fecaca);
        }

        .log-entry.warning {
            border-right-color: var(--warning-color);
            background: linear-gradient(135deg, #fef3c7, #fde68a);
        }

        .log-entry.success {
            border-right-color: var(--secondary-color);
            background: linear-gradient(135deg, #d1fae5, #a7f3d0);
        }

        .log-entry.info {
            border-right-color: var(--info-color);
            background: linear-gradient(135deg, #dbeafe, #bfdbfe);
        }

        .log-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .log-type {
            font-weight: 700;
            font-size: 1.1rem;
        }

        .log-time {
            color: var(--gray-color);
            font-size: 0.9rem;
        }

        .log-user {
            display: inline-block;
            padding: 4px 12px;
            background: #f3f4f6;
            border-radius: 20px;
            font-size: 0.85rem;
            margin-bottom: 10px;
        }

        .log-description {
            margin-bottom: 10px;
            line-height: 1.6;
        }

        .log-details {
            display: flex;
            gap: 15px;
            font-size: 0.85rem;
            color: var(--gray-color);
        }

        .log-ip {
            font-family: monospace;
            background: #f9fafb;
            padding: 2px 8px;
            border-radius: 4px;
        }

        .log-actions {
            margin-top: 15px;
            display: flex;
            gap: 10px;
        }

        .btn-sm {
            padding: 6px 12px;
            font-size: 0.85rem;
        }

        .empty-logs {
            text-align: center;
            padding: 60px 20px;
            color: var(--gray-color);
        }

        .empty-logs i {
            font-size: 3rem;
            margin-bottom: 20px;
            opacity: 0.5;
        }

        .log-severity-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            margin-left: 10px;
        }

        .severity-critical { background: #fee2e2; color: #991b1b; }
        .severity-high { background: #fef3c7; color: #92400e; }
        .severity-medium { background: #dbeafe; color: #1e40af; }
        .severity-low { background: #d1fae5; color: #065f46; }

        .pagination {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-top: 30px;
        }

        .page-link {
            padding: 10px 15px;
            background: #f3f4f6;
            border-radius: 8px;
            text-decoration: none;
            color: var(--dark-color);
            transition: var(--transition);
        }

        .page-link:hover {
            background: var(--primary-color);
            color: white;
        }

        .page-link.active {
            background: var(--primary-color);
            color: white;
        }

        .logs-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: white;
            border-radius: var(--border-radius);
            padding: 20px;
            text-align: center;
            box-shadow: var(--box-shadow);
        }

        .stat-value {
            font-size: 2rem;
            font-weight: 800;
            margin-bottom: 5px;
        }

        .stat-label {
            color: var(--gray-color);
            font-size: 0.9rem;
        }

        @media (max-width: 768px) {
            .filters-grid {
                grid-template-columns: 1fr;
            }
            
            .filter-actions {
                flex-direction: column;
            }
            
            .log-details {
                flex-direction: column;
                gap: 5px;
            }
            
            .logs-stats {
                grid-template-columns: repeat(2, 1fr);
            }
        }
    </style>
</head>
<body>
        <?php include 'components/sidebar.php'; ?>


    <div class="main-content">
        <div class="top-bar">
            <div class="page-title">
                <h2><i class="fas fa-clipboard-list"></i> سجلات النظام</h2>
                <p>مراقبة وتحليل جميع أحداث النظام</p>
            </div>
            
            <div class="quick-actions">
                <button class="action-btn danger" onclick="openModal('deleteLogsModal')">
                    <i class="fas fa-trash-alt"></i> حذف سجلات قديمة
                </button>
                <button class="action-btn primary" onclick="openModal('exportLogsModal')">
                    <i class="fas fa-download"></i> تصدير السجلات
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

        <!-- إحصائيات السجلات -->
        <div class="logs-stats">
            <?php
            $totalLogs = 0;
            $criticalLogs = 0;
            $warningLogs = 0;
            $successLogs = 0;
            
            foreach ($logStats as $stat) {
                $totalLogs += $stat['total_logs'];
                $criticalLogs += $stat['critical_logs'];
                $warningLogs += $stat['warning_logs'];
                $successLogs += $stat['success_logs'];
            }
            ?>
            <div class="stat-card">
                <div class="stat-value"><?php echo number_format($totalLogs); ?></div>
                <div class="stat-label">إجمالي السجلات (7 أيام)</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--danger-color);"><?php echo number_format($criticalLogs); ?></div>
                <div class="stat-label">سجلات حرجة</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--warning-color);"><?php echo number_format($warningLogs); ?></div>
                <div class="stat-label">سجلات تحذيرية</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--secondary-color);"><?php echo number_format($successLogs); ?></div>
                <div class="stat-label">سجلات ناجحة</div>
            </div>
        </div>

        <!-- فلاتر السجلات -->
        <div class="logs-filters">
            <form method="GET" action="">
                <div class="filters-grid">
                    <div class="filter-group">
                        <label class="filter-label">نوع السجل</label>
                        <select name="type" class="filter-control">
                            <option value="">جميع الأنواع</option>
                            <?php foreach ($logTypes as $type): ?>
                            <option value="<?php echo htmlspecialchars($type); ?>" 
                                    <?php echo $logType === $type ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($type); ?>
                            </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    
                    <div class="filter-group">
                        <label class="filter-label">مستوى الخطورة</label>
                        <select name="severity" class="filter-control">
                            <option value="">جميع المستويات</option>
                            <option value="high" <?php echo $severity === 'high' ? 'selected' : ''; ?>>حرج</option>
                            <option value="medium" <?php echo $severity === 'medium' ? 'selected' : ''; ?>>متوسط</option>
                            <option value="low" <?php echo $severity === 'low' ? 'selected' : ''; ?>>منخفض</option>
                        </select>
                    </div>
                    
                    <div class="filter-group">
                        <label class="filter-label">من تاريخ</label>
                        <input type="date" name="start_date" class="filter-control" 
                               value="<?php echo htmlspecialchars($startDate); ?>">
                    </div>
                    
                    <div class="filter-group">
                        <label class="filter-label">إلى تاريخ</label>
                        <input type="date" name="end_date" class="filter-control" 
                               value="<?php echo htmlspecialchars($endDate); ?>">
                    </div>
                    
                    <div class="filter-group">
                        <label class="filter-label">بحث</label>
                        <input type="text" name="search" class="filter-control" 
                               placeholder="وصف أو IP أو بريد..."
                               value="<?php echo htmlspecialchars($search); ?>">
                    </div>
                    
                    <div class="filter-group">
                        <label class="filter-label">المستخدم</label>
                        <select name="user_id" class="filter-control">
                            <option value="all">جميع المستخدمين</option>
                            <?php foreach ($usersWithLogs as $userLog): ?>
                            <option value="<?php echo $userLog['id']; ?>" 
                                    <?php echo $userId == $userLog['id'] ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($userLog['email']); ?>
                            </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>
                
                <div class="filter-actions">
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-search"></i> تطبيق الفلاتر
                    </button>
                    <a href="logs.php" class="btn btn-secondary">
                        <i class="fas fa-redo"></i> إعادة تعيين
                    </a>
                    <button type="button" class="btn btn-info" onclick="realtimeMonitoring()">
                        <i class="fas fa-broadcast-tower"></i> مراقبة حية
                    </button>
                </div>
            </form>
        </div>

        <!-- قائمة السجلات -->
        <div class="section">
            <div class="section-header">
                <div class="section-title">
                    <i class="fas fa-history"></i>
                    <h3>السجلات (<?php echo count($logs); ?>)</h3>
                </div>
                <div style="color: var(--gray-color); font-size: 0.9rem;">
                    آخر تحديث: <?php echo date('H:i:s'); ?>
                </div>
            </div>
            
            <?php if (empty($logs)): ?>
            <div class="empty-logs">
                <i class="fas fa-clipboard-list"></i>
                <h3>لا توجد سجلات</h3>
                <p>لا توجد سجلات مطابقة لمعايير البحث المحددة.</p>
            </div>
            <?php else: ?>
                <?php foreach ($logs as $log): 
                    // تحديد مستوى الخطورة
                    $logType = strtolower($log['action_type']);
                    if (strpos($logType, 'fail') !== false || strpos($logType, 'block') !== false || strpos($logType, 'lock') !== false) {
                        $severity = 'critical';
                        $severityClass = 'critical';
                        $severityText = 'حرج';
                    } elseif (strpos($logType, 'warn') !== false || strpos($logType, 'attempt') !== false) {
                        $severity = 'warning';
                        $severityClass = 'warning';
                        $severityText = 'تحذير';
                    } elseif (strpos($logType, 'success') !== false) {
                        $severity = 'success';
                        $severityClass = 'success';
                        $severityText = 'نجاح';
                    } else {
                        $severity = 'info';
                        $severityClass = 'info';
                        $severityText = 'معلومات';
                    }
                ?>
                <div class="log-entry <?php echo $severityClass; ?>">
                    <div class="log-header">
                        <div>
                            <span class="log-type"><?php echo htmlspecialchars($log['action_type']); ?></span>
                            <span class="log-severity-badge severity-<?php echo $severity; ?>">
                                <?php echo $severityText; ?>
                            </span>
                        </div>
                        <div class="log-time">
                            <?php echo $log['log_time']; ?>
                        </div>
                    </div>
                    
                    <?php if ($log['user_email']): ?>
                    <div class="log-user">
                        <i class="fas fa-user"></i>
                        <?php echo htmlspecialchars($log['user_email']); ?>
                        <small>(<?php echo $log['user_role']; ?>)</small>
                    </div>
                    <?php endif; ?>
                    
                    <div class="log-description">
                        <?php echo htmlspecialchars($log['description']); ?>
                    </div>
                    
                    <div class="log-details">
                        <div class="log-ip">
                            <i class="fas fa-network-wired"></i>
                            <?php echo htmlspecialchars($log['ip_address']); ?>
                        </div>
                        
                        <?php if ($log['user_agent']): ?>
                        <div>
                            <i class="fas fa-desktop"></i>
                            <?php echo htmlspecialchars(substr($log['user_agent'], 0, 50)); ?>...
                        </div>
                        <?php endif; ?>
                    </div>
                    
                    <div class="log-actions">
                        <button class="btn btn-sm btn-secondary" onclick="viewLogDetails(<?php echo $log['id']; ?>)">
                            <i class="fas fa-eye"></i> تفاصيل
                        </button>
                        <button class="btn btn-sm btn-info" onclick="analyzeLog(<?php echo $log['id']; ?>)">
                            <i class="fas fa-chart-bar"></i> تحليل
                        </button>
                        <?php if ($severity === 'critical' || $severity === 'warning'): ?>
                        <button class="btn btn-sm btn-danger" onclick="investigateLog(<?php echo $log['id']; ?>)">
                            <i class="fas fa-search"></i> تحقيق
                        </button>
                        <?php endif; ?>
                    </div>
                </div>
                <?php endforeach; ?>
            <?php endif; ?>
            
            <!-- الترقيم -->
            <div class="pagination">
                <a href="?page=1" class="page-link">« الأولى</a>
                <a href="?page=1" class="page-link active">1</a>
                <a href="?page=2" class="page-link">2</a>
                <a href="?page=3" class="page-link">3</a>
                <a href="?page=2" class="page-link">الأخيرة »</a>
            </div>
        </div>
    </div>

    <!-- نافذة حذف السجلات القديمة -->
    <div id="deleteLogsModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <div class="modal-title"><i class="fas fa-trash-alt"></i> حذف سجلات قديمة</div>
                <button class="close-modal" onclick="closeModal('deleteLogsModal')">&times;</button>
            </div>
            <form method="POST" action="">
                <div style="padding: 20px;">
                    <div class="form-group">
                        <label class="form-label">حذف السجلات الأقدم من</label>
                        <select name="delete_days" class="form-control" required>
                            <option value="30">شهر (30 يوماً)</option>
                            <option value="90">3 أشهر (90 يوماً)</option>
                            <option value="180">6 أشهر (180 يوماً)</option>
                            <option value="365">سنة (365 يوماً)</option>
                        </select>
                    </div>
                    <div class="alert" style="background: #fee2e2; color: #991b1b; padding: 15px; border-radius: 8px; margin-top: 20px;">
                        <i class="fas fa-exclamation-triangle"></i>
                        <strong>تحذير:</strong> هذا الإجراء لا يمكن التراجع عنه. سيتم حذف جميع السجلات الأقدم من الفترة المحددة بشكل دائم.
                    </div>
                    <div style="text-align: center; margin-top: 25px;">
                        <button type="button" class="btn btn-secondary" onclick="closeModal('deleteLogsModal')">إلغاء</button>
                        <button type="submit" name="delete_old_logs" class="btn btn-danger">تأكيد الحذف</button>
                    </div>
                </div>
            </form>
        </div>
    </div>

    <!-- نافذة تصدير السجلات -->
    <div id="exportLogsModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <div class="modal-title"><i class="fas fa-download"></i> تصدير السجلات</div>
                <button class="close-modal" onclick="closeModal('exportLogsModal')">&times;</button>
            </div>
            <form method="POST" action="">
                <div style="padding: 20px;">
                    <div class="form-group">
                        <label class="form-label">تنسيق الملف</label>
                        <select name="format" class="form-control" required>
                            <option value="csv">CSV (مفصول بفواصل)</option>
                            <option value="json">JSON</option>
                            <option value="xml">XML</option>
                            <option value="pdf">PDF</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">نطاق البيانات</label>
                        <select class="form-control">
                            <option>السجلات المصفاة حالياً (<?php echo count($logs); ?> سجل)</option>
                            <option>آخر 24 ساعة</option>
                            <option>آخر أسبوع</option>
                            <option>آخر شهر</option>
                            <option>جميع السجلات</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="checkbox-label">
                            <input type="checkbox" checked> تضمين جميع الحقول
                        </label>
                    </div>
                    <div style="text-align: center; margin-top: 25px;">
                        <button type="button" class="btn btn-secondary" onclick="closeModal('exportLogsModal')">إلغاء</button>
                        <button type="submit" name="export_logs" class="btn btn-primary">تصدير</button>
                    </div>
                </div>
            </form>
        </div>
    </div>

    <!-- نافذة تفاصيل السجل -->
    <div id="logDetailsModal" class="modal">
        <div class="modal-content" style="max-width: 700px;">
            <div class="modal-header">
                <div class="modal-title"><i class="fas fa-file-alt"></i> تفاصيل السجل</div>
                <button class="close-modal" onclick="closeModal('logDetailsModal')">&times;</button>
            </div>
            <div style="padding: 20px;">
                <div id="logDetailsContent">
                    <!-- سيتم تحميل المحتوى هنا عبر AJAX -->
                </div>
            </div>
        </div>
    </div>

    <script>
        // إظهار وإخفاء النماذج
        function openModal(modalId) {
            document.getElementById(modalId).style.display = 'flex';
        }
        
        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }
        
        // عرض تفاصيل السجل
        function viewLogDetails(logId) {
            // في الواقع، ستقوم بجلب البيانات عبر AJAX
            const modalContent = `
                <div class="log-entry info">
                    <div class="log-header">
                        <div>
                            <span class="log-type">LOGIN_FAILURE</span>
                            <span class="log-severity-badge severity-critical">حرج</span>
                        </div>
                        <div class="log-time">2024-01-15 14:30:45</div>
                    </div>
                    
                    <div class="log-user">
                        <i class="fas fa-user"></i>
                        user@example.com (student)
                    </div>
                    
                    <div class="log-description">
                        فشل محاولة دخول بكلمة مرور خاطئة للمستخدم user@example.com
                    </div>
                    
                    <div class="log-details">
                        <div class="log-ip">
                            <i class="fas fa-network-wired"></i>
                            192.168.1.100
                        </div>
                        <div>
                            <i class="fas fa-desktop"></i>
                            Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
                        </div>
                    </div>
                    
                    <div style="margin-top: 20px; padding: 15px; background: #f9fafb; border-radius: 8px;">
                        <h4 style="margin-bottom: 10px; color: var(--dark-color);">معلومات إضافية:</h4>
                        <p><strong>البلد المقدر:</strong> السعودية</p>
                        <p><strong>المزود:</strong> شركة الاتصالات السعودية</p>
                        <p><strong>المتصفح:</strong> Chrome 120</p>
                        <p><strong>نظام التشغيل:</strong> Windows 10</p>
                        <p><strong>جهاز:</strong> كمبيوتر مكتبي</p>
                    </div>
                    
                    <div style="margin-top: 20px; padding: 15px; background: #fef3c7; border-radius: 8px;">
                        <h4 style="margin-bottom: 10px; color: #92400e;"><i class="fas fa-exclamation-triangle"></i> توصيات:</h4>
                        <ul style="margin-right: 20px;">
                            <li>التحقق من هوية المستخدم</li>
                            <li>إرسال تنبيه للمستخدم عن محاولة الدخول الفاشلة</li>
                            <li>مراقبة النشاط من عنوان IP هذا</li>
                        </ul>
                    </div>
                </div>
            `;
            
            document.getElementById('logDetailsContent').innerHTML = modalContent;
            openModal('logDetailsModal');
        }
        
        // تحليل السجل
        function analyzeLog(logId) {
            alert(`جاري تحليل السجل #${logId}...\n\nسيتم عرض تحليل الأنماط والتوصيات الأمنية.`);
            // في الواقع، ستقوم بجلب التحليل عبر AJAX
        }
        
        // تحقيق في السجل
        function investigateLog(logId) {
            if (confirm(`بدء تحقيق في السجل #${logId}?\n\nسيتم جمع معلومات إضافية وتحليل الأنماط.`)) {
                // في الواقع، ستقوم ببدء عملية التحقيق
                alert('تم بدء التحقيق. سيتم إعلامك عند اكتمال النتائج.');
            }
        }
        
        // مراقبة حية للسجلات
        function realtimeMonitoring() {
            const modalContent = `
                <div class="modal" id="realtimeModal" style="display: flex;">
                    <div class="modal-content" style="max-width: 800px;">
                        <div class="modal-header">
                            <div class="modal-title"><i class="fas fa-broadcast-tower"></i> مراقبة السجلات الحية</div>
                            <button class="close-modal" onclick="closeModal('realtimeModal')">&times;</button>
                        </div>
                        <div style="padding: 20px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                                <div>
                                    <button class="btn btn-primary" onclick="startMonitoring()">
                                        <i class="fas fa-play"></i> بدء المراقبة
                                    </button>
                                    <button class="btn btn-secondary" onclick="stopMonitoring()">
                                        <i class="fas fa-stop"></i> إيقاف
                                    </button>
                                </div>
                                <div style="color: var(--secondary-color);">
                                    <i class="fas fa-circle" style="font-size: 0.8rem;"></i> نشط الآن
                                </div>
                            </div>
                            
                            <div id="realtimeLogs" style="max-height: 400px; overflow-y: auto; padding: 15px; background: #1f2937; border-radius: 8px; font-family: monospace; color: white;">
                                <div style="color: #10b981;">[14:30:45] LOGIN_SUCCESS - user@example.com</div>
                                <div style="color: #ef4444;">[14:30:40] LOGIN_FAILURE - attacker@example.com</div>
                                <div style="color: #f59e0b;">[14:30:35] PASSWORD_RESET_REQUEST - admin@example.com</div>
                                <div style="color: #10b981;">[14:30:30] USER_REGISTERED - newuser@example.com</div>
                                <div style="color: #3b82f6;">[14:30:25] SECURITY_SCAN - system</div>
                            </div>
                            
                            <div style="margin-top: 20px; display: flex; gap: 15px;">
                                <div style="flex: 1; padding: 15px; background: #f9fafb; border-radius: 8px;">
                                    <div style="font-size: 0.9rem; color: var(--gray-color);">السجلات/ثانية</div>
                                    <div style="font-size: 1.5rem; font-weight: bold;">2.5</div>
                                </div>
                                <div style="flex: 1; padding: 15px; background: #f9fafb; border-radius: 8px;">
                                    <div style="font-size: 0.9rem; color: var(--gray-color);">سجلات حرجة</div>
                                    <div style="font-size: 1.5rem; font-weight: bold; color: var(--danger-color);">3</div>
                                </div>
                                <div style="flex: 1; padding: 15px; background: #f9fafb; border-radius: 8px;">
                                    <div style="font-size: 0.9rem; color: var(--gray-color);">وقت التشغيل</div>
                                    <div style="font-size: 1.5rem; font-weight: bold;">00:02:30</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.insertAdjacentHTML('beforeend', modalContent);
        }
        
        // بدء المراقبة الحية
        function startMonitoring() {
            alert('بدء المراقبة الحية للسجلات...');
            // في الواقع، ستقوم بالاتصال بـ WebSocket أو Server-Sent Events
        }
        
        function stopMonitoring() {
            alert('إيقاف المراقبة الحية.');
            closeModal('realtimeModal');
        }
        
        // إغلاق النماذج عند النقر خارجها
        window.onclick = function(event) {
            const modals = document.querySelectorAll('.modal');
            modals.forEach(modal => {
                if (event.target === modal) {
                    modal.style.display = 'none';
                }
            });
        };
        
        // تحديث السجلات كل 30 ثانية
        setInterval(() => {
            if (document.getElementById('realtimeLogs')) {
                const now = new Date();
                const timeString = now.toLocaleTimeString('ar-SA', { hour12: false });
                const logEntry = `<div style="color: #${Math.floor(Math.random()*16777215).toString(16)};">[${timeString}] TEST_LOG - system</div>`;
                document.getElementById('realtimeLogs').insertAdjacentHTML('afterbegin', logEntry);
            }
        }, 30000);
    </script>
</body>
</html>