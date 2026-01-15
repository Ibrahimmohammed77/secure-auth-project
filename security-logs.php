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

// الحصول على سجل الأمان للمستخدم
$pdo = Database::getInstance();
$stmt = $pdo->prepare("SELECT * FROM security_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 50");
$stmt->execute([$user['id']]);
$logs = $stmt->fetchAll();

// الحصول على إحصائيات
$stmt = $pdo->prepare("
    SELECT 
        COUNT(*) as total_logs,
        SUM(CASE WHEN action_type = 'LOGIN_SUCCESS' THEN 1 ELSE 0 END) as successful_logins,
        SUM(CASE WHEN action_type = 'LOGIN_FAILED' THEN 1 ELSE 0 END) as failed_logins,
        MIN(created_at) as first_log
    FROM security_logs 
    WHERE user_id = ?
");
$stmt->execute([$user['id']]);
$stats = $stmt->fetch();
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>سجل الأمان</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Arial', sans-serif;
            background: #f5f7fa;
            color: #333;
            min-height: 100vh;
        }
        
        .navbar {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        
        .navbar-brand {
            font-size: 1.5rem;
            font-weight: bold;
        }
        
        .user-menu a {
            color: white;
            text-decoration: none;
            margin-right: 20px;
        }
        
        .user-menu a:hover {
            text-decoration: underline;
        }
        
        .container {
            max-width: 1200px;
            margin: 40px auto;
            padding: 0 20px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
            text-align: center;
        }
        
        .stat-card .value {
            font-size: 2rem;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 10px;
        }
        
        .stat-card .label {
            color: #666;
            font-size: 1rem;
        }
        
        .logs-section {
            background: white;
            border-radius: 15px;
            padding: 40px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
        }
        
        .logs-section h2 {
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #f0f0f0;
        }
        
        .logs-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .logs-table th {
            background: #f8f9fa;
            padding: 15px;
            text-align: right;
            color: #555;
            font-weight: bold;
            border-bottom: 2px solid #e9ecef;
        }
        
        .logs-table td {
            padding: 15px;
            border-bottom: 1px solid #e9ecef;
            color: #666;
        }
        
        .logs-table tr:hover {
            background: #f8f9fa;
        }
        
        .log-type {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 50px;
            font-size: 0.9rem;
            font-weight: bold;
        }
        
        .type-success {
            background: #e8f5e9;
            color: #2e7d32;
        }
        
        .type-warning {
            background: #fff3e0;
            color: #ef6c00;
        }
        
        .type-danger {
            background: #ffebee;
            color: #c62828;
        }
        
        .type-info {
            background: #e3f2fd;
            color: #1565c0;
        }
        
        .no-logs {
            text-align: center;
            padding: 40px;
            color: #999;
        }
        
        .pagination {
            display: flex;
            justify-content: center;
            margin-top: 20px;
            gap: 10px;
        }
        
        .pagination button {
            padding: 10px 20px;
            border: 1px solid #ddd;
            background: white;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .pagination button:hover {
            background: #f0f0f0;
        }
        
        .pagination button.active {
            background: #667eea;
            color: white;
            border-color: #667eea;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 0 10px;
            }
            
            .logs-section {
                padding: 20px;
            }
            
            .logs-table {
                display: block;
                overflow-x: auto;
            }
            
            .logs-table th,
            .logs-table td {
                padding: 10px;
                font-size: 14px;
            }
            
            .navbar {
                flex-direction: column;
                gap: 15px;
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="navbar-brand">
            سجل الأمان
        </div>
        <div class="user-menu">
            <a href="dashboard.php">العودة للوحة التحكم</a>
            <a href="logout.php">تسجيل الخروج</a>
        </div>
    </nav>
    
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="value"><?php echo $stats['total_logs'] ?? 0; ?></div>
                <div class="label">إجمالي الأحداث</div>
            </div>
            
            <div class="stat-card">
                <div class="value"><?php echo $stats['successful_logins'] ?? 0; ?></div>
                <div class="label">عمليات دخول ناجحة</div>
            </div>
            
            <div class="stat-card">
                <div class="value"><?php echo $stats['failed_logins'] ?? 0; ?></div>
                <div class="label">محاولات فاشلة</div>
            </div>
            
            <div class="stat-card">
                <div class="value">
                    <?php 
                    if ($stats['first_log']) {
                        echo date('Y-m-d', strtotime($stats['first_log']));
                    } else {
                        echo 'لا يوجد';
                    }
                    ?>
                </div>
                <div class="label">أول حدث</div>
            </div>
        </div>
        
        <div class="logs-section">
            <h2>آخر الأحداث الأمنية</h2>
            
            <?php if (empty($logs)): ?>
                <div class="no-logs">
                    <p>لا توجد أحداث مسجلة حتى الآن</p>
                </div>
            <?php else: ?>
                <table class="logs-table">
                    <thead>
                        <tr>
                            <th>التاريخ والوقت</th>
                            <th>نوع الحدث</th>
                            <th>الوصف</th>
                            <th>عنوان IP</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($logs as $log): ?>
                        <tr>
                            <td><?php echo date('Y-m-d H:i:s', strtotime($log['created_at'])); ?></td>
                            <td>
                                <?php
                                $typeClass = 'type-info';
                                $typeText = $log['action_type'];
                                
                                if (strpos($log['action_type'], 'SUCCESS') !== false) {
                                    $typeClass = 'type-success';
                                } elseif (strpos($log['action_type'], 'FAIL') !== false) {
                                    $typeClass = 'type-danger';
                                } elseif (strpos($log['action_type'], 'WARNING') !== false) {
                                    $typeClass = 'type-warning';
                                }
                                
                                $actionNames = [
                                    'LOGIN_SUCCESS' => 'تسجيل دخول ناجح',
                                    'LOGIN_FAILED' => 'تسجيل دخول فاشل',
                                    'PASSWORD_CHANGED' => 'تغيير كلمة المرور',
                                    'PASSWORD_RESET' => 'إعادة تعيين كلمة المرور',
                                    'MFA_ENABLED' => 'تفعيل المصادقة الثنائية',
                                    'LOGOUT' => 'تسجيل الخروج',
                                    'REGISTRATION' => 'تسجيل مستخدم جديد'
                                ];
                                
                                $typeText = $actionNames[$log['action_type']] ?? $log['action_type'];
                                ?>
                                <span class="log-type <?php echo $typeClass; ?>">
                                    <?php echo htmlspecialchars($typeText); ?>
                                </span>
                            </td>
                            <td><?php echo htmlspecialchars($log['description']); ?></td>
                            <td><?php echo htmlspecialchars($log['ip_address']); ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>