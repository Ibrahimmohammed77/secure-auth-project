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

// الحصول على الجلسات النشطة للمستخدم
$pdo = Database::getInstance();
$stmt = $pdo->prepare("
    SELECT * FROM user_sessions 
    WHERE user_id = ? AND expires_at > NOW() AND is_revoked = FALSE 
    ORDER BY created_at DESC
");
$stmt->execute([$user['id']]);
$sessions = $stmt->fetchAll();

// إبطال جلسة معينة
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['revoke_session'])) {
    $sessionId = $_POST['session_id'];
    
    $stmt = $pdo->prepare("UPDATE user_sessions SET is_revoked = TRUE WHERE id = ? AND user_id = ?");
    $stmt->execute([$sessionId, $user['id']]);
    
    // إذا كانت الجلسة المبطلة هي الجلسة الحالية، توجيه لتسجيل الخروج
    if ($_COOKIE['session_token'] === $sessionId) {
        header('Location: logout.php');
        exit;
    }
    
    header('Location: sessions.php?success=1');
    exit;
}

// إبطال جميع الجلسات عدا الحالية
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['revoke_all'])) {
    $currentToken = $_COOKIE['session_token'];
    
    $stmt = $pdo->prepare("
        UPDATE user_sessions 
        SET is_revoked = TRUE 
        WHERE user_id = ? 
        AND session_token != ? 
        AND expires_at > NOW() 
        AND is_revoked = FALSE
    ");
    $stmt->execute([$user['id'], $currentToken]);
    
    header('Location: sessions.php?success=2');
    exit;
}
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>الجلسات النشطة</title>
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
        
        .alert {
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .alert-success {
            background: #e8f5e9;
            color: #2e7d32;
            border: 1px solid #c8e6c9;
        }
        
        .sessions-section {
            background: white;
            border-radius: 15px;
            padding: 40px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
        }
        
        .sessions-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }
        
        .sessions-header h2 {
            color: #333;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn-danger {
            background: #f44336;
            color: white;
        }
        
        .btn-danger:hover {
            background: #d32f2f;
        }
        
        .sessions-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .sessions-table th {
            background: #f8f9fa;
            padding: 15px;
            text-align: right;
            color: #555;
            font-weight: bold;
            border-bottom: 2px solid #e9ecef;
        }
        
        .sessions-table td {
            padding: 15px;
            border-bottom: 1px solid #e9ecef;
            color: #666;
        }
        
        .sessions-table tr:hover {
            background: #f8f9fa;
        }
        
        .session-status {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 50px;
            font-size: 0.9rem;
            font-weight: bold;
        }
        
        .status-active {
            background: #e8f5e9;
            color: #2e7d32;
        }
        
        .status-current {
            background: #e3f2fd;
            color: #1565c0;
        }
        
        .status-expired {
            background: #f5f5f5;
            color: #757575;
        }
        
        .session-actions form {
            display: inline;
        }
        
        .btn-sm {
            padding: 5px 15px;
            font-size: 14px;
        }
        
        .no-sessions {
            text-align: center;
            padding: 40px;
            color: #999;
        }
        
        .device-info {
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 0 10px;
            }
            
            .sessions-section {
                padding: 20px;
            }
            
            .sessions-table {
                display: block;
                overflow-x: auto;
            }
            
            .sessions-table th,
            .sessions-table td {
                padding: 10px;
                font-size: 14px;
            }
            
            .sessions-header {
                flex-direction: column;
                gap: 15px;
                text-align: center;
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
            الجلسات النشطة
        </div>
        <div class="user-menu">
            <a href="dashboard.php">العودة للوحة التحكم</a>
            <a href="logout.php">تسجيل الخروج</a>
        </div>
    </nav>
    
    <div class="container">
        <?php if (isset($_GET['success'])): ?>
            <div class="alert alert-success">
                <?php 
                if ($_GET['success'] == 1) {
                    echo 'تم إبطال الجلسة بنجاح';
                } elseif ($_GET['success'] == 2) {
                    echo 'تم إبطال جميع الجلسات الأخرى بنجاح';
                }
                ?>
            </div>
        <?php endif; ?>
        
        <div class="sessions-section">
            <div class="sessions-header">
                <h2>الجلسات النشطة على حسابك</h2>
                <?php if (count($sessions) > 1): ?>
                <form method="POST" onsubmit="return confirm('هل أنت متأكد من إبطال جميع الجلسات الأخرى؟');">
                    <button type="submit" name="revoke_all" class="btn btn-danger">
                        إبطال جميع الجلسات الأخرى
                    </button>
                </form>
                <?php endif; ?>
            </div>
            
            <?php if (empty($sessions)): ?>
                <div class="no-sessions">
                    <p>لا توجد جلسات نشطة</p>
                </div>
            <?php else: ?>
                <table class="sessions-table">
                    <thead>
                        <tr>
                            <th>الحالة</th>
                            <th>الجهاز</th>
                            <th>عنوان IP</th>
                            <th>وقت البدء</th>
                            <th>ينتهي في</th>
                            <th>الإجراءات</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php 
                        $currentToken = $_COOKIE['session_token'];
                        foreach ($sessions as $session): 
                            $isCurrent = $session['session_token'] === $currentToken;
                        ?>
                        <tr>
                            <td>
                                <span class="session-status <?php echo $isCurrent ? 'status-current' : 'status-active'; ?>">
                                    <?php echo $isCurrent ? 'هذه الجلسة' : 'نشطة'; ?>
                                </span>
                            </td>
                            <td class="device-info" title="<?php echo htmlspecialchars($session['user_agent']); ?>">
                                <?php
                                $ua = $session['user_agent'];
                                $device = 'جهاز غير معروف';
                                
                                if (strpos($ua, 'Windows') !== false) $device = '💻 Windows';
                                elseif (strpos($ua, 'Mac') !== false) $device = '🍎 Mac';
                                elseif (strpos($ua, 'Linux') !== false) $device = '🐧 Linux';
                                elseif (strpos($ua, 'iPhone') !== false || strpos($ua, 'iPad') !== false) $device = '📱 iOS';
                                elseif (strpos($ua, 'Android') !== false) $device = '📱 Android';
                                
                                echo $device;
                                ?>
                            </td>
                            <td><?php echo htmlspecialchars($session['ip_address']); ?></td>
                            <td><?php echo date('Y-m-d H:i', strtotime($session['created_at'])); ?></td>
                            <td><?php echo date('Y-m-d H:i', strtotime($session['expires_at'])); ?></td>
                            <td class="session-actions">
                                <?php if (!$isCurrent): ?>
                                <form method="POST" onsubmit="return confirm('هل أنت متأكد من إبطال هذه الجلسة؟');" style="display: inline;">
                                    <input type="hidden" name="session_id" value="<?php echo $session['session_token']; ?>">
                                    <button type="submit" name="revoke_session" class="btn btn-danger btn-sm">
                                        إبطال
                                    </button>
                                </form>
                                <?php else: ?>
                                <span style="color: #999;">(الجلسة الحالية)</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
            
            <div style="margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 10px;">
                <h3>💡 معلومات مهمة:</h3>
                <ul style="margin-top: 10px; padding-right: 20px; color: #666;">
                    <li>الجلسات تنتهي تلقائيًا بعد 24 ساعة من عدم النشاط</li>
                    <li>عند تغيير كلمة المرور، يتم إبطال جميع الجلسات تلقائيًا</li>
                    <li>يمكنك إبطال أي جلسة من أجهزة أخرى للبقاء آمنًا</li>
                    <li>الجلسة الحالية لا يمكن إبطالها من هذه الصفحة</li>
                </ul>
            </div>
        </div>
    </div>
</body>
</html>