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

// تحديد الفترة الزمنية
$period = $_GET['period'] ?? 'week';
$startDate = $_GET['start_date'] ?? '';
$endDate = $_GET['end_date'] ?? '';

// حساب التواريخ بناءً على الفترة
$now = new DateTime();
if ($period === 'day') {
    $startDate = $now->format('Y-m-d');
    $endDate = $now->format('Y-m-d');
} elseif ($period === 'week') {
    $startDate = $now->modify('-7 days')->format('Y-m-d');
    $endDate = date('Y-m-d');
} elseif ($period === 'month') {
    $startDate = $now->modify('-30 days')->format('Y-m-d');
    $endDate = date('Y-m-d');
} elseif ($period === 'year') {
    $startDate = $now->modify('-365 days')->format('Y-m-d');
    $endDate = date('Y-m-d');
}

// إحصائيات التسجيلات
$stmt = $pdo->prepare("
    SELECT 
        DATE(created_at) as date,
        COUNT(*) as registrations,
        SUM(CASE WHEN role = 'student' THEN 1 ELSE 0 END) as students,
        SUM(CASE WHEN role = 'teacher' THEN 1 ELSE 0 END) as teachers
    FROM users 
    WHERE created_at BETWEEN ? AND ?
    GROUP BY DATE(created_at)
    ORDER BY date
");
$stmt->execute([$startDate . ' 00:00:00', $endDate . ' 23:59:59']);
$registrationStats = $stmt->fetchAll();

// إحصائيات الدخول
$stmt = $pdo->prepare("
    SELECT 
        DATE(attempted_at) as date,
        COUNT(*) as total_attempts,
        SUM(CASE WHEN attempt_status = 'success' THEN 1 ELSE 0 END) as successful,
        SUM(CASE WHEN attempt_status = 'wrong_password' THEN 1 ELSE 0 END) as failed
    FROM login_attempts 
    WHERE attempted_at BETWEEN ? AND ?
    GROUP BY DATE(attempted_at)
    ORDER BY date
");
$stmt->execute([$startDate . ' 00:00:00', $endDate . ' 23:59:59']);
$loginStats = $stmt->fetchAll();

// إحصائيات الأمان
$stmt = $pdo->prepare("
    SELECT 
        action_type,
        COUNT(*) as count,
        DATE(created_at) as date
    FROM security_logs 
    WHERE created_at BETWEEN ? AND ?
    GROUP BY action_type, DATE(created_at)
    ORDER BY count DESC
");
$stmt->execute([$startDate . ' 00:00:00', $endDate . ' 23:59:59']);
$securityStats = $stmt->fetchAll();

// إحصائيات النشاط
$stmt = $pdo->prepare("
    SELECT 
        HOUR(created_at) as hour,
        COUNT(*) as activity_count
    FROM security_logs 
    WHERE created_at BETWEEN ? AND ?
    GROUP BY HOUR(created_at)
    ORDER BY hour
");
$stmt->execute([$startDate . ' 00:00:00', $endDate . ' 23:59:59']);
$activityStats = $stmt->fetchAll();

// إحصائيات الجلسات
$stmt = $pdo->prepare("
    SELECT 
        DATE(created_at) as date,
        COUNT(*) as sessions_created,
        COUNT(DISTINCT user_id) as unique_users,
        AVG(TIMESTAMPDIFF(MINUTE, created_at, expires_at)) as avg_session_duration
    FROM user_sessions 
    WHERE created_at BETWEEN ? AND ?
    GROUP BY DATE(created_at)
    ORDER BY date
");
$stmt->execute([$startDate . ' 00:00:00', $endDate . ' 23:59:59']);
$sessionStats = $stmt->fetchAll();

// معالجة تصدير التقرير
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['export_report'])) {
    $reportType = $_POST['report_type'];
    $format = $_POST['format'];

    if ($format === 'csv') {
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename=report_' . date('Y-m-d') . '.csv');

        $output = fopen('php://output', 'w');

        if ($reportType === 'registrations') {
            fputcsv($output, ['التاريخ', 'إجمالي التسجيلات', 'طلاب', 'مدرسين']);
            foreach ($registrationStats as $stat) {
                fputcsv($output, [
                    $stat['date'],
                    $stat['registrations'],
                    $stat['students'],
                    $stat['teachers']
                ]);
            }
        } elseif ($reportType === 'logins') {
            fputcsv($output, ['التاريخ', 'إجمالي المحاولات', 'ناجح', 'فاشل', 'نسبة النجاح']);
            foreach ($loginStats as $stat) {
                $successRate = $stat['total_attempts'] > 0 ?
                    round(($stat['successful'] / $stat['total_attempts']) * 100, 2) : 0;
                fputcsv($output, [
                    $stat['date'],
                    $stat['total_attempts'],
                    $stat['successful'],
                    $stat['failed'],
                    $successRate . '%'
                ]);
            }
        }

        fclose($output);
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>التقارير - لوحة التحكم</title>
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

        .period-selector {
            background: white;
            border-radius: var(--border-radius);
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: var(--box-shadow);
        }

        .period-tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            overflow-x: auto;
        }

        .period-tab {
            padding: 10px 20px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            background: none;
            cursor: pointer;
            transition: var(--transition);
            white-space: nowrap;
        }

        .period-tab.active {
            background: var(--primary-color);
            color: white;
            border-color: var(--primary-color);
        }

        .period-tab:hover:not(.active) {
            background: #f9fafb;
        }

        .date-range {
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
        }

        .date-input {
            padding: 10px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            font-size: 1rem;
        }

        .report-card {
            background: white;
            border-radius: var(--border-radius);
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: var(--box-shadow);
        }

        .report-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #f3f4f6;
        }

        .report-title {
            font-size: 1.3rem;
            font-weight: 700;
            color: var(--dark-color);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .report-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .stat-item {
            text-align: center;
            padding: 20px;
            background: #f9fafb;
            border-radius: 10px;
        }

        .stat-value {
            font-size: 2rem;
            font-weight: 800;
            color: var(--primary-color);
            margin-bottom: 5px;
        }

        .stat-label {
            color: var(--gray-color);
            font-size: 0.95rem;
        }

        .stat-change {
            font-size: 0.9rem;
            margin-top: 5px;
        }

        .change-up {
            color: var(--secondary-color);
        }

        .change-down {
            color: var(--danger-color);
        }

        .chart-placeholder {
            height: 300px;
            background: linear-gradient(135deg, #f9fafb, #f3f4f6);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--gray-color);
            margin-top: 20px;
        }

        .export-options {
            display: flex;
            gap: 15px;
            align-items: center;
            margin-top: 20px;
        }

        .export-btn {
            padding: 10px 20px;
            background: var(--primary-color);
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: var(--transition);
        }

        .export-btn:hover {
            background: var(--primary-dark);
            transform: translateY(-2px);
        }

        .format-select {
            padding: 10px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            background: white;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
            margin-bottom: 30px;
        }

        .summary-card {
            background: white;
            border-radius: var(--border-radius);
            padding: 25px;
            box-shadow: var(--box-shadow);
        }

        .summary-card h3 {
            margin-bottom: 20px;
            color: var(--dark-color);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .summary-list {
            list-style: none;
        }

        .summary-list li {
            padding: 12px 0;
            border-bottom: 1px solid #f3f4f6;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .summary-list li:last-child {
            border-bottom: none;
        }

        .list-value {
            font-weight: 600;
            color: var(--dark-color);
        }

        @media (max-width: 768px) {
            .date-range {
                flex-direction: column;
                align-items: stretch;
            }

            .period-tabs {
                flex-wrap: wrap;
            }

            .export-options {
                flex-direction: column;
                align-items: stretch;
            }
        }
    </style>
</head>

<body>
    <?php include 'components/sidebar.php'; ?>


    <div class="main-content">
        <div class="top-bar">
            <div class="page-title">
                <h2><i class="fas fa-chart-bar"></i> التقارير والإحصائيات</h2>
                <p>تحليل وإحصاءات النظام الشاملة</p>
            </div>

            <div class="quick-actions">
                <button class="action-btn primary" onclick="generateCustomReport()">
                    <i class="fas fa-file-export"></i> تقرير مخصص
                </button>
                <button class="action-btn" onclick="printReport()">
                    <i class="fas fa-print"></i> طباعة التقرير
                </button>
            </div>
        </div>

        <!-- اختيار الفترة -->
        <div class="period-selector">
            <h3 style="margin-bottom: 20px; color: var(--dark-color);">
                <i class="fas fa-calendar-alt"></i> اختيار الفترة الزمنية
            </h3>

            <div class="period-tabs">
                <button class="period-tab <?php echo $period === 'day' ? 'active' : ''; ?>"
                    onclick="setPeriod('day')">
                    <i class="fas fa-sun"></i> اليوم
                </button>
                <button class="period-tab <?php echo $period === 'week' ? 'active' : ''; ?>"
                    onclick="setPeriod('week')">
                    <i class="fas fa-calendar-week"></i> آخر أسبوع
                </button>
                <button class="period-tab <?php echo $period === 'month' ? 'active' : ''; ?>"
                    onclick="setPeriod('month')">
                    <i class="fas fa-calendar"></i> آخر شهر
                </button>
                <button class="period-tab <?php echo $period === 'year' ? 'active' : ''; ?>"
                    onclick="setPeriod('year')">
                    <i class="fas fa-calendar-alt"></i> آخر سنة
                </button>
                <button class="period-tab <?php echo $period === 'custom' ? 'active' : ''; ?>"
                    onclick="showCustomRange()">
                    <i class="fas fa-cog"></i> مخصص
                </button>
            </div>

            <form method="GET" action="" id="dateForm">
                <input type="hidden" name="period" id="period" value="<?php echo $period; ?>">

                <div id="customRange" style="display: <?php echo $period === 'custom' ? 'block' : 'none'; ?>;">
                    <div class="date-range">
                        <div>
                            <label style="display: block; margin-bottom: 5px; font-weight: 600;">من تاريخ</label>
                            <input type="date" name="start_date" class="date-input"
                                value="<?php echo htmlspecialchars($startDate); ?>" required>
                        </div>
                        <div>
                            <label style="display: block; margin-bottom: 5px; font-weight: 600;">إلى تاريخ</label>
                            <input type="date" name="end_date" class="date-input"
                                value="<?php echo htmlspecialchars($endDate); ?>" required>
                        </div>
                        <div style="align-self: flex-end;">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-search"></i> تطبيق
                            </button>
                        </div>
                    </div>
                </div>
            </form>
        </div>

        <!-- ملخص سريع -->
        <div class="summary-grid">
            <div class="summary-card">
                <h3><i class="fas fa-users"></i> ملخص المستخدمين</h3>
                <ul class="summary-list">
                    <?php
                    // إجمالي التسجيلات
                    $totalRegistrations = array_sum(array_column($registrationStats, 'registrations'));
                    ?>
                    <li>
                        <span>إجمالي التسجيلات</span>
                        <span class="list-value"><?php echo number_format($totalRegistrations); ?></span>
                    </li>
                    <li>
                        <span>متوسط يومي</span>
                        <span class="list-value">
                            <?php
                            $days = max(1, count($registrationStats));
                            echo number_format($totalRegistrations / $days, 1);
                            ?>
                        </span>
                    </li>
                    <li>
                        <span>طلاب جدد</span>
                        <span class="list-value">
                            <?php echo number_format(array_sum(array_column($registrationStats, 'students'))); ?>
                        </span>
                    </li>
                    <li>
                        <span>مدرسين جدد</span>
                        <span class="list-value">
                            <?php echo number_format(array_sum(array_column($registrationStats, 'teachers'))); ?>
                        </span>
                    </li>
                </ul>
            </div>

            <div class="summary-card">
                <h3><i class="fas fa-sign-in-alt"></i> ملخص الدخول</h3>
                <ul class="summary-list">
                    <?php
                    // إجمالي المحاولات
                    $totalAttempts = array_sum(array_column($loginStats, 'total_attempts'));
                    $successfulAttempts = array_sum(array_column($loginStats, 'successful'));
                    $failedAttempts = array_sum(array_column($loginStats, 'failed'));
                    $successRate = $totalAttempts > 0 ? round(($successfulAttempts / $totalAttempts) * 100, 2) : 0;
                    ?>
                    <li>
                        <span>إجمالي المحاولات</span>
                        <span class="list-value"><?php echo number_format($totalAttempts); ?></span>
                    </li>
                    <li>
                        <span>ناجحة</span>
                        <span class="list-value" style="color: var(--secondary-color);">
                            <?php echo number_format($successfulAttempts); ?>
                        </span>
                    </li>
                    <li>
                        <span>فاشلة</span>
                        <span class="list-value" style="color: var(--danger-color);">
                            <?php echo number_format($failedAttempts); ?>
                        </span>
                    </li>
                    <li>
                        <span>نسبة النجاح</span>
                        <span class="list-value"><?php echo $successRate; ?>%</span>
                    </li>
                </ul>
            </div>

            <div class="summary-card">
                <h3><i class="fas fa-shield-alt"></i> ملخص الأمان</h3>
                <ul class="summary-list">
                    <?php
                    // تحليل أحداث الأمان
                    $securityEvents = [];
                    foreach ($securityStats as $stat) {
                        if (!isset($securityEvents[$stat['action_type']])) {
                            $securityEvents[$stat['action_type']] = 0;
                        }
                        $securityEvents[$stat['action_type']] += $stat['count'];
                    }
                    arsort($securityEvents);
                    ?>
                    <li>
                        <span>إجمالي الأحداث</span>
                        <span class="list-value"><?php echo number_format(array_sum($securityEvents)); ?></span>
                    </li>
                    <?php $i = 0;
                    foreach ($securityEvents as $event => $count): ?>
                        <?php if ($i++ < 3): ?>
                            <li>
                                <span><?php echo htmlspecialchars($event); ?></span>
                                <span class="list-value"><?php echo number_format($count); ?></span>
                            </li>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </ul>
            </div>
        </div>

        <!-- تقرير التسجيلات -->
        <div class="report-card">
            <div class="report-header">
                <div class="report-title">
                    <i class="fas fa-user-plus"></i>
                    <h3>تقرير التسجيلات</h3>
                </div>
                <form method="POST" action="" class="export-options">
                    <input type="hidden" name="report_type" value="registrations">
                    <select name="format" class="format-select">
                        <option value="csv">CSV</option>
                        <option value="pdf">PDF</option>
                        <option value="excel">Excel</option>
                    </select>
                    <button type="submit" name="export_report" class="export-btn">
                        <i class="fas fa-download"></i> تصدير التقرير
                    </button>
                </form>
            </div>

            <div class="report-stats">
                <div class="stat-item">
                    <div class="stat-value"><?php echo number_format($totalRegistrations); ?></div>
                    <div class="stat-label">إجمالي التسجيلات</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value"><?php echo number_format(array_sum(array_column($registrationStats, 'students'))); ?></div>
                    <div class="stat-label">طلاب جدد</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value"><?php echo number_format(array_sum(array_column($registrationStats, 'teachers'))); ?></div>
                    <div class="stat-label">مدرسين جدد</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">
                        <?php
                        $days = max(1, count($registrationStats));
                        echo number_format($totalRegistrations / $days, 1);
                        ?>
                    </div>
                    <div class="stat-label">متوسط يومي</div>
                </div>
            </div>

            <div class="chart-placeholder">
                <div style="text-align: center;">
                    <i class="fas fa-chart-line fa-3x" style="color: var(--primary-color); margin-bottom: 15px;"></i>
                    <p>مخطط التسجيلات حسب التاريخ</p>
                    <small>سيظهر هنا مخطط تفصيلي عند تفعيل مكتبة المخططات المتقدمة</small>
                </div>
            </div>
        </div>

        <!-- تقرير الدخول -->
        <div class="report-card">
            <div class="report-header">
                <div class="report-title">
                    <i class="fas fa-sign-in-alt"></i>
                    <h3>تقرير محاولات الدخول</h3>
                </div>
                <form method="POST" action="" class="export-options">
                    <input type="hidden" name="report_type" value="logins">
                    <select name="format" class="format-select">
                        <option value="csv">CSV</option>
                        <option value="pdf">PDF</option>
                        <option value="excel">Excel</option>
                    </select>
                    <button type="submit" name="export_report" class="export-btn">
                        <i class="fas fa-download"></i> تصدير التقرير
                    </button>
                </form>
            </div>

            <div class="report-stats">
                <div class="stat-item">
                    <div class="stat-value"><?php echo number_format($totalAttempts); ?></div>
                    <div class="stat-label">إجمالي المحاولات</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" style="color: var(--secondary-color);">
                        <?php echo number_format($successfulAttempts); ?>
                    </div>
                    <div class="stat-label">دخول ناجح</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" style="color: var(--danger-color);">
                        <?php echo number_format($failedAttempts); ?>
                    </div>
                    <div class="stat-label">دخول فاشل</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value"><?php echo $successRate; ?>%</div>
                    <div class="stat-label">نسبة النجاح</div>
                </div>
            </div>

            <div class="chart-placeholder">
                <div style="text-align: center;">
                    <i class="fas fa-chart-pie fa-3x" style="color: var(--primary-color); margin-bottom: 15px;"></i>
                    <p>مخطط توزيع محاولات الدخول</p>
                    <small>سيظهر هنا مخطط تفصيلي عند تفعيل مكتبة المخططات المتقدمة</small>
                </div>
            </div>
        </div>

        <!-- تقرير النشاط -->
        <div class="report-card">
            <div class="report-header">
                <div class="report-title">
                    <i class="fas fa-chart-line"></i>
                    <h3>تقرير النشاط اليومي</h3>
                </div>
                <button class="export-btn" onclick="exportActivityReport()">
                    <i class="fas fa-download"></i> تصدير النشاط
                </button>
            </div>

            <div style="margin-top: 20px;">
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="background: #f9fafb;">
                            <th style="padding: 15px; text-align: right; border-bottom: 2px solid #e5e7eb;">الساعة</th>
                            <th style="padding: 15px; text-align: right; border-bottom: 2px solid #e5e7eb;">عدد الأنشطة</th>
                            <th style="padding: 15px; text-align: right; border-bottom: 2px solid #e5e7eb;">مستوى النشاط</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        $activityByHour = [];
                        foreach ($activityStats as $stat) {
                            $activityByHour[$stat['hour']] = $stat['activity_count'];
                        }

                        for ($hour = 0; $hour < 24; $hour++):
                            $count = $activityByHour[$hour] ?? 0;
                            $activityLevel = $count > 50 ? 'عالي' : ($count > 20 ? 'متوسط' : 'منخفض');
                            $color = $count > 50 ? 'var(--secondary-color)' : ($count > 20 ? 'var(--warning-color)' : 'var(--gray-color)');
                        ?>
                            <tr>
                                <td style="padding: 12px; border-bottom: 1px solid #f3f4f6;">
                                    <?php printf('%02d:00 - %02d:59', $hour, $hour); ?>
                                </td>
                                <td style="padding: 12px; border-bottom: 1px solid #f3f4f6; font-weight: 600;">
                                    <?php echo number_format($count); ?>
                                </td>
                                <td style="padding: 12px; border-bottom: 1px solid #f3f4f6;">
                                    <span style="color: <?php echo $color; ?>; font-weight: 600;">
                                        <?php echo $activityLevel; ?>
                                    </span>
                                </td>
                            </tr>
                        <?php endfor; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- تقرير الجلسات -->
        <div class="report-card">
            <div class="report-header">
                <div class="report-title">
                    <i class="fas fa-clock"></i>
                    <h3>تقرير الجلسات</h3>
                </div>
            </div>

            <div style="margin-top: 20px;">
                <div class="report-stats">
                    <?php
                    $totalSessions = array_sum(array_column($sessionStats, 'sessions_created'));
                    $totalUniqueUsers = array_sum(array_column($sessionStats, 'unique_users'));
                    $avgSessionDuration = array_sum(array_column($sessionStats, 'avg_session_duration')) / max(1, count($sessionStats));
                    ?>
                    <div class="stat-item">
                        <div class="stat-value"><?php echo number_format($totalSessions); ?></div>
                        <div class="stat-label">إجمالي الجلسات</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value"><?php echo number_format($totalUniqueUsers); ?></div>
                        <div class="stat-label">مستخدمين متفردين</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value"><?php echo round($avgSessionDuration, 1); ?></div>
                        <div class="stat-label">متوسط مدة الجلسة (دقيقة)</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">
                            <?php echo $totalSessions > 0 ? round($totalUniqueUsers / $totalSessions * 100, 1) : 0; ?>%
                        </div>
                        <div class="stat-label">تفرد المستخدمين</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // وظائف الفترة الزمنية
        function setPeriod(period) {
            document.getElementById('period').value = period;
            document.getElementById('dateForm').submit();
        }

        function showCustomRange() {
            document.getElementById('period').value = 'custom';
            document.getElementById('customRange').style.display = 'block';

            // إخفاء التبويبات الأخرى
            const tabs = document.querySelectorAll('.period-tab');
            tabs.forEach(tab => {
                if (tab.textContent.includes('مخصص')) {
                    tab.classList.add('active');
                } else {
                    tab.classList.remove('active');
                }
            });
        }

        // طباعة التقرير
        function printReport() {
            window.print();
        }

        // تصدير تقرير النشاط
        function exportActivityReport() {
            // في الواقع، ستقوم بإنشاء ملف CSV أو Excel
            alert('جاري تصدير تقرير النشاط...');

            // محاكاة التصدير
            setTimeout(() => {
                const link = document.createElement('a');
                link.href = 'export.php?type=activity&period=<?php echo $period; ?>';
                link.download = 'activity_report_<?php echo date("Y-m-d"); ?>.csv';
                link.click();
            }, 1000);
        }

        // تقرير مخصص
        function generateCustomReport() {
            const modalContent = `
                <div class="modal" id="customReportModal" style="display: flex;">
                    <div class="modal-content" style="max-width: 600px;">
                        <div class="modal-header">
                            <div class="modal-title"><i class="fas fa-file-export"></i> تقرير مخصص</div>
                            <button class="close-modal" onclick="closeModal('customReportModal')">&times;</button>
                        </div>
                        <form method="POST" action="generate-custom-report.php">
                            <div class="form-group">
                                <label class="form-label">نوع التقرير</label>
                                <select name="report_type" class="form-control" required>
                                    <option value="">اختر نوع التقرير...</option>
                                    <option value="user_activity">نشاط المستخدمين</option>
                                    <option value="security_events">أحداث الأمان</option>
                                    <option value="login_patterns">أنماط الدخول</option>
                                    <option value="system_performance">أداء النظام</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label class="form-label">الفترة الزمنية</label>
                                <div style="display: flex; gap: 10px;">
                                    <input type="date" name="custom_start" class="form-control" required>
                                    <span style="align-self: center;">إلى</span>
                                    <input type="date" name="custom_end" class="form-control" required>
                                </div>
                            </div>
                            <div class="form-group">
                                <label class="form-label">تنسيق الملف</label>
                                <select name="file_format" class="form-control" required>
                                    <option value="csv">CSV</option>
                                    <option value="pdf">PDF</option>
                                    <option value="excel">Excel</option>
                                    <option value="json">JSON</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label class="form-label">خيارات إضافية</label>
                                <div style="display: flex; flex-direction: column; gap: 10px;">
                                    <label>
                                        <input type="checkbox" name="include_charts"> تضمين المخططات البيانية
                                    </label>
                                    <label>
                                        <input type="checkbox" name="include_summary"> تضمين ملخص تنفيذي
                                    </label>
                                    <label>
                                        <input type="checkbox" name="group_by_day"> تجميع البيانات يومياً
                                    </label>
                                </div>
                            </div>
                            <div class="form-actions">
                                <button type="button" class="btn btn-secondary" onclick="closeModal('customReportModal')">إلغاء</button>
                                <button type="submit" class="btn btn-primary">إنشاء التقرير</button>
                            </div>
                        </form>
                    </div>
                </div>
            `;

            document.body.insertAdjacentHTML('beforeend', modalContent);
        }

        // إغلاق النماذج
        function closeModal(modalId) {
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.style.display = 'none';
                setTimeout(() => modal.remove(), 300);
            }
        }

        // تحميل البيانات حسب الفترة عند تغييرها
        document.querySelectorAll('.period-tab').forEach(tab => {
            tab.addEventListener('click', function() {
                const period = this.textContent.includes('اليوم') ? 'day' :
                    this.textContent.includes('أسبوع') ? 'week' :
                    this.textContent.includes('شهر') ? 'month' :
                    this.textContent.includes('سنة') ? 'year' : 'custom';
                setPeriod(period);
            });
        });

        // تحديث التقرير كل 5 دقائق إذا كان الفاصل يومي
        <?php if ($period === 'day'): ?>
            setTimeout(() => {
                location.reload();
            }, 300000);
        <?php endif; ?>
    </script>
</body>

</html>