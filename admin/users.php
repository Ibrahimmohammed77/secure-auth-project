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

// البحث والتصفية
$search = $_GET['search'] ?? '';
$role = $_GET['role'] ?? '';
$status = $_GET['status'] ?? '';

// بناء الاستعلام
$query = "SELECT * FROM users WHERE 1=1";
$params = [];

if (!empty($search)) {
    $query .= " AND (email LIKE :search OR username LIKE :search)";
    $params[':search'] = "%$search%";
}

if (!empty($role)) {
    $query .= " AND role = :role";
    $params[':role'] = $role;
}

if (!empty($status)) {
    if ($status === 'active') {
        $query .= " AND is_active = TRUE";
    } elseif ($status === 'inactive') {
        $query .= " AND is_active = FALSE";
    } elseif ($status === 'locked') {
        $query .= " AND account_locked_until IS NOT NULL AND account_locked_until > NOW()";
    }
}

$query .= " ORDER BY created_at DESC";
$stmt = $pdo->prepare($query);
$stmt->execute($params);
$users = $stmt->fetchAll();

// معالجة الإجراءات
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['toggle_status'])) {
        $userId = $_POST['user_id'];
        $action = $_POST['action'];
        
        $newStatus = $action === 'activate' ? 1 : 0;
        $stmt = $pdo->prepare("UPDATE users SET is_active = ? WHERE id = ?");
        $stmt->execute([$newStatus, $userId]);
        
        $statusText = $action === 'activate' ? 'تفعيل' : 'تعطيل';
        $auth->logSecurityEvent($user['id'], 'USER_STATUS_CHANGE', "تم $statusText للمستخدم ID: $userId");
        
        $_SESSION['success_message'] = "تم $statusText الحساب بنجاح";
        header('Location: users.php');
        exit;
    }
    
    if (isset($_POST['reset_password'])) {
        $userId = $_POST['user_id'];
        
        // إنشاء كلمة مرور مؤقتة
        $tempPassword = bin2hex(random_bytes(4));
        $hashedPassword = password_hash($tempPassword, PASSWORD_BCRYPT, ['cost' => 12]);
        
        $stmt = $pdo->prepare("UPDATE users SET password_hash = ?, last_password_change = NOW() WHERE id = ?");
        $stmt->execute([$hashedPassword, $userId]);
        
        // إبطال جميع جلسات المستخدم
        $stmt = $pdo->prepare("UPDATE user_sessions SET is_revoked = TRUE WHERE user_id = ?");
        $stmt->execute([$userId]);
        
        $auth->logSecurityEvent($user['id'], 'PASSWORD_RESET_ADMIN', "تم إعادة تعيين كلمة مرور المستخدم ID: $userId");
        
        $_SESSION['temp_password'] = $tempPassword;
        $_SESSION['reset_user_id'] = $userId;
        
        header('Location: users.php?show_password=true');
        exit;
    }
    
    if (isset($_POST['delete_user'])) {
        $userId = $_POST['user_id'];
        
        // الحصول على معلومات المستخدم قبل الحذف
        $stmt = $pdo->prepare("SELECT email FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $userToDelete = $stmt->fetch();
        
        // حذف المستخدم (في بيئة حقيقية، قد نفضل التعطيل بدلاً من الحذف)
        $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        
        $auth->logSecurityEvent($user['id'], 'USER_DELETED', "تم حذف المستخدم: " . $userToDelete['email']);
        
        $_SESSION['success_message'] = "تم حذف المستخدم بنجاح";
        header('Location: users.php');
        exit;
    }
    
    if (isset($_POST['export_users'])) {
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename=users_' . date('Y-m-d') . '.csv');
        
        $output = fopen('php://output', 'w');
        fputcsv($output, ['ID', 'البريد الإلكتروني', 'اسم المستخدم', 'الدور', 'الحالة', 'تفعيل MFA', 'آخر دخول', 'تاريخ الإنشاء']);
        
        foreach ($users as $userRow) {
            fputcsv($output, [
                $userRow['id'],
                $userRow['email'],
                $userRow['username'] ?? 'N/A',
                $userRow['role'],
                $userRow['is_active'] ? 'نشط' : 'غير نشط',
                $userRow['mfa_enabled'] ? 'مفعل' : 'غير مفعل',
                $userRow['last_login_at'] ?? 'لم يدخل بعد',
                $userRow['created_at']
            ]);
        }
        
        fclose($output);
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
    <title>إدارة المستخدمين - لوحة التحكم</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="../assets/css/admin.css">

    <style>
        /* ستستخدم نفس الأنماط من security-dashboard.php */
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

        /* ستنسيقات مشتركة - نستخدم نفس أنماط security-dashboard */
        /* ... نفس الأنماط السابقة ... */
        
        .filters-card {
            background: white;
            border-radius: var(--border-radius);
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: var(--box-shadow);
        }
        
        .filters-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
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
            padding: 12px 16px;
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
        }
        
        .user-role-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        
        .role-student { background: #dbeafe; color: #1e40af; }
        .role-teacher { background: #fef3c7; color: #92400e; }
        .role-admin { background: #f3e8ff; color: #6b21a8; }
        
        .user-status-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        
        .status-active { background: #d1fae5; color: #065f46; }
        .status-inactive { background: #fee2e2; color: #991b1b; }
        .status-locked { background: #fef3c7; color: #92400e; }
        
        .action-dropdown {
            position: relative;
            display: inline-block;
        }
        
        .action-btn {
            padding: 8px 16px;
            background: var(--primary-color);
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            transition: var(--transition);
        }
        
        .action-btn:hover {
            background: var(--primary-dark);
        }
        
        .dropdown-content {
            display: none;
            position: absolute;
            background: white;
            min-width: 200px;
            box-shadow: 0 8px 16px rgba(0,0,0,0.2);
            z-index: 1000;
            border-radius: 8px;
            overflow: hidden;
        }
        
        .dropdown-content a {
            display: block;
            padding: 12px 16px;
            text-decoration: none;
            color: var(--dark-color);
            transition: var(--transition);
        }
        
        .dropdown-content a:hover {
            background: #f9fafb;
        }
        
        .show { display: block; }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            right: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            z-index: 2000;
            align-items: center;
            justify-content: center;
        }
        
        .modal-content {
            background: white;
            border-radius: var(--border-radius);
            width: 90%;
            max-width: 500px;
            padding: 30px;
            animation: slideUp 0.3s ease;
        }
        
        .temp-password-box {
            background: linear-gradient(135deg, #fef3c7, #fde68a);
            border: 2px dashed #f59e0b;
            border-radius: var(--border-radius);
            padding: 20px;
            margin: 20px 0;
            text-align: center;
        }
        
        .temp-password {
            font-family: monospace;
            font-size: 1.5rem;
            font-weight: bold;
            color: #92400e;
            letter-spacing: 2px;
            padding: 10px;
            background: white;
            border-radius: 8px;
            margin: 10px 0;
        }
        
        .copy-btn {
            background: var(--primary-color);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            transition: var(--transition);
        }
        
        .copy-btn:hover {
            background: var(--primary-dark);
        }
        
        .copy-btn.copied {
            background: var(--secondary-color);
        }
    </style>
</head>
<body>
    <!-- استخدم نفس الهيكل مع الشريط الجانبي -->
    <?php include_once 'components/sidebar.php';?>

    <div class="main-content">
        <div class="top-bar">
            <div class="page-title">
                <h2><i class="fas fa-users"></i> إدارة المستخدمين</h2>
                <p>عرض وإدارة جميع مستخدمي النظام</p>
            </div>
            
            <div class="quick-actions">
                <button class="action-btn primary" onclick="openModal('addUserModal')">
                    <i class="fas fa-user-plus"></i> إضافة مستخدم
                </button>
                <form method="POST" style="display: inline;">
                    <button type="submit" name="export_users" class="action-btn">
                        <i class="fas fa-download"></i> تصدير البيانات
                    </button>
                </form>
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

        <!-- فلاتر البحث -->
        <div class="filters-card">
            <form method="GET" action="">
                <div class="filters-grid">
                    <div class="filter-group">
                        <label class="filter-label">بحث</label>
                        <input type="text" name="search" class="filter-control" 
                               placeholder="البريد الإلكتروني أو اسم المستخدم..."
                               value="<?php echo htmlspecialchars($search); ?>">
                    </div>
                    
                    <div class="filter-group">
                        <label class="filter-label">الدور</label>
                        <select name="role" class="filter-control">
                            <option value="">جميع الأدوار</option>
                            <option value="student" <?php echo $role === 'student' ? 'selected' : ''; ?>>طالب</option>
                            <option value="teacher" <?php echo $role === 'teacher' ? 'selected' : ''; ?>>مدرس</option>
                            <option value="admin" <?php echo $role === 'admin' ? 'selected' : ''; ?>>مدير</option>
                        </select>
                    </div>
                    
                    <div class="filter-group">
                        <label class="filter-label">الحالة</label>
                        <select name="status" class="filter-control">
                            <option value="">جميع الحالات</option>
                            <option value="active" <?php echo $status === 'active' ? 'selected' : ''; ?>>نشط</option>
                            <option value="inactive" <?php echo $status === 'inactive' ? 'selected' : ''; ?>>غير نشط</option>
                            <option value="locked" <?php echo $status === 'locked' ? 'selected' : ''; ?>>مقفل</option>
                        </select>
                    </div>
                </div>
                
                <div class="filter-actions">
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-search"></i> بحث
                    </button>
                    <a href="users.php" class="btn btn-secondary">
                        <i class="fas fa-redo"></i> إعادة تعيين
                    </a>
                </div>
            </form>
        </div>

        <!-- جدول المستخدمين -->
        <div class="section">
            <div class="section-header">
                <div class="section-title">
                    <i class="fas fa-users-cog"></i>
                    <h3>المستخدمين (<?php echo count($users); ?>)</h3>
                </div>
            </div>
            
            <div class="table-responsive">
                <table class="table">
                    <thead>
                        <tr>
                            <th>المعرف</th>
                            <th>البريد الإلكتروني</th>
                            <th>اسم المستخدم</th>
                            <th>الدور</th>
                            <th>الحالة</th>
                            <th>MFA</th>
                            <th>آخر دخول</th>
                            <th>تاريخ الإنشاء</th>
                            <th>الإجراءات</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($users)): ?>
                        <tr>
                            <td colspan="9" style="text-align: center; padding: 40px;">
                                <i class="fas fa-users-slash fa-2x" style="color: var(--gray-color); margin-bottom: 15px;"></i>
                                <p>لا توجد نتائج مطابقة للبحث</p>
                            </td>
                        </tr>
                        <?php else: ?>
                            <?php foreach ($users as $userRow): ?>
                            <tr>
                                <td><?php echo $userRow['id']; ?></td>
                                <td>
                                    <strong><?php echo htmlspecialchars($userRow['email']); ?></strong>
                                    <?php if ($userRow['is_active'] == 0): ?>
                                    <br><small style="color: var(--danger-color);">غير مفعل</small>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo htmlspecialchars($userRow['username'] ?? 'N/A'); ?></td>
                                <td>
                                    <span class="user-role-badge role-<?php echo $userRow['role']; ?>">
                                        <i class="fas fa-<?php echo $userRow['role'] === 'admin' ? 'crown' : ($userRow['role'] === 'teacher' ? 'chalkboard-teacher' : 'user-graduate'); ?>"></i>
                                        <?php 
                                        $roleNames = [
                                            'student' => 'طالب',
                                            'teacher' => 'مدرس',
                                            'admin' => 'مدير'
                                        ];
                                        echo $roleNames[$userRow['role']];
                                        ?>
                                    </span>
                                </td>
                                <td>
                                    <?php 
                                    if ($userRow['account_locked_until'] && strtotime($userRow['account_locked_until']) > time()) {
                                        echo '<span class="user-status-badge status-locked"><i class="fas fa-lock"></i> مقفل</span>';
                                    } elseif ($userRow['is_active']) {
                                        echo '<span class="user-status-badge status-active"><i class="fas fa-check-circle"></i> نشط</span>';
                                    } else {
                                        echo '<span class="user-status-badge status-inactive"><i class="fas fa-times-circle"></i> غير نشط</span>';
                                    }
                                    ?>
                                </td>
                                <td>
                                    <?php if ($userRow['mfa_enabled']): ?>
                                    <span class="status-badge status-low"><i class="fas fa-lock"></i> مفعل</span>
                                    <?php else: ?>
                                    <span class="status-badge status-neutral"><i class="fas fa-unlock"></i> غير مفعل</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php 
                                    if ($userRow['last_login_at']) {
                                        echo date('Y-m-d H:i', strtotime($userRow['last_login_at']));
                                    } else {
                                        echo '<span style="color: var(--gray-color);">لم يدخل بعد</span>';
                                    }
                                    ?>
                                </td>
                                <td><?php echo date('Y-m-d', strtotime($userRow['created_at'])); ?></td>
                                <td>
                                    <div class="action-dropdown">
                                        <button class="action-btn" onclick="toggleDropdown('actions-<?php echo $userRow['id']; ?>')">
                                            <i class="fas fa-cog"></i> إجراءات
                                        </button>
                                        <div id="actions-<?php echo $userRow['id']; ?>" class="dropdown-content">
                                            <a href="user-details.php?id=<?php echo $userRow['id']; ?>">
                                                <i class="fas fa-eye"></i> عرض التفاصيل
                                            </a>
                                            <?php if ($userRow['is_active']): ?>
                                            <a href="#" onclick="deactivateUser(<?php echo $userRow['id']; ?>, '<?php echo htmlspecialchars($userRow['email']); ?>')">
                                                <i class="fas fa-user-slash"></i> تعطيل الحساب
                                            </a>
                                            <?php else: ?>
                                            <a href="#" onclick="activateUser(<?php echo $userRow['id']; ?>, '<?php echo htmlspecialchars($userRow['email']); ?>')">
                                                <i class="fas fa-user-check"></i> تفعيل الحساب
                                            </a>
                                            <?php endif; ?>
                                            <a href="#" onclick="resetPassword(<?php echo $userRow['id']; ?>, '<?php echo htmlspecialchars($userRow['email']); ?>')">
                                                <i class="fas fa-key"></i> إعادة تعيين كلمة المرور
                                            </a>
                                            <hr>
                                            <a href="#" onclick="deleteUser(<?php echo $userRow['id']; ?>, '<?php echo htmlspecialchars($userRow['email']); ?>')" style="color: var(--danger-color);">
                                                <i class="fas fa-trash-alt"></i> حذف الحساب
                                            </a>
                                        </div>
                                    </div>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            
            <!-- الترقيم الصفحات -->
            <div style="display: flex; justify-content: center; margin-top: 30px;">
                <nav>
                    <ul style="display: flex; gap: 10px; list-style: none;">
                        <li><a href="?page=1" style="padding: 10px 15px; background: #f3f4f6; border-radius: 6px; text-decoration: none; color: var(--dark-color);">«</a></li>
                        <li><a href="?page=1" style="padding: 10px 15px; background: var(--primary-color); color: white; border-radius: 6px; text-decoration: none;">1</a></li>
                        <li><a href="?page=2" style="padding: 10px 15px; background: #f3f4f6; border-radius: 6px; text-decoration: none; color: var(--dark-color);">2</a></li>
                        <li><a href="?page=3" style="padding: 10px 15px; background: #f3f4f6; border-radius: 6px; text-decoration: none; color: var(--dark-color);">3</a></li>
                        <li><a href="?page=2" style="padding: 10px 15px; background: #f3f4f6; border-radius: 6px; text-decoration: none; color: var(--dark-color);">»</a></li>
                    </ul>
                </nav>
            </div>
        </div>
    </div>

    <!-- نافذة عرض كلمة المرور المؤقتة -->
    <?php if (isset($_GET['show_password']) && isset($_SESSION['temp_password'])): ?>
    <div id="passwordModal" class="modal" style="display: flex;">
        <div class="modal-content">
            <div class="modal-header">
                <div class="modal-title"><i class="fas fa-key"></i> كلمة المرور المؤقتة</div>
                <button class="close-modal" onclick="closeModal('passwordModal')">&times;</button>
            </div>
            <div class="temp-password-box">
                <h3>تم إنشاء كلمة مرور مؤقتة</h3>
                <p>شارك هذه الكلمة مع المستخدم. يجب عليه تغييرها فور تسجيل الدخول.</p>
                <div class="temp-password" id="tempPassword">
                    <?php echo htmlspecialchars($_SESSION['temp_password']); ?>
                </div>
                <button class="copy-btn" onclick="copyPassword()">
                    <i class="fas fa-copy"></i> نسخ إلى الحافظة
                </button>
            </div>
            <div style="text-align: center; margin-top: 20px;">
                <button class="btn btn-primary" onclick="closeModal('passwordModal')">
                    <i class="fas fa-check"></i> تم
                </button>
            </div>
        </div>
    </div>
    <?php 
    unset($_SESSION['temp_password']);
    unset($_SESSION['reset_user_id']);
    endif; ?>

    <!-- نافذة إضافة مستخدم -->
    <div id="addUserModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <div class="modal-title"><i class="fas fa-user-plus"></i> إضافة مستخدم جديد</div>
                <button class="close-modal" onclick="closeModal('addUserModal')">&times;</button>
            </div>
            <form method="POST" action="add-user.php">
                <div class="form-group">
                    <label class="form-label">البريد الإلكتروني *</label>
                    <input type="email" name="email" class="form-control" required placeholder="user@example.com">
                </div>
                <div class="form-group">
                    <label class="form-label">اسم المستخدم (اختياري)</label>
                    <input type="text" name="username" class="form-control" placeholder="الاسم المعروض">
                </div>
                <div class="form-group">
                    <label class="form-label">الدور *</label>
                    <select name="role" class="form-control" required>
                        <option value="student">طالب</option>
                        <option value="teacher">مدرس</option>
                        <option value="admin">مدير</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">كلمة المرور *</label>
                    <input type="text" name="password" class="form-control" value="<?php echo bin2hex(random_bytes(4)); ?>" required>
                    <small style="color: var(--gray-color);">سيتم إنشاء كلمة مرور عشوائية</small>
                </div>
                <div class="form-group">
                    <label class="form-label">
                        <input type="checkbox" name="send_welcome_email"> إرسال بريد ترحيبي
                    </label>
                </div>
                <div class="form-actions">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('addUserModal')">إلغاء</button>
                    <button type="submit" class="btn btn-primary">إضافة المستخدم</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        // وظائف القوائم المنسدلة
        function toggleDropdown(dropdownId) {
            const dropdown = document.getElementById(dropdownId);
            dropdown.classList.toggle('show');
        }
        
        // إغلاق القوائم المنسدلة عند النقر خارجها
        window.onclick = function(event) {
            if (!event.target.matches('.action-btn')) {
                const dropdowns = document.getElementsByClassName('dropdown-content');
                for (let dropdown of dropdowns) {
                    if (dropdown.classList.contains('show')) {
                        dropdown.classList.remove('show');
                    }
                }
            }
        };
        
        // وظائف الإجراءات
        function activateUser(userId, email) {
            if (confirm(`هل تريد تفعيل حساب ${email}؟`)) {
                const form = document.createElement('form');
                form.method = 'POST';
                form.style.display = 'none';
                
                const userIdInput = document.createElement('input');
                userIdInput.type = 'hidden';
                userIdInput.name = 'user_id';
                userIdInput.value = userId;
                
                const actionInput = document.createElement('input');
                actionInput.type = 'hidden';
                actionInput.name = 'action';
                actionInput.value = 'activate';
                
                const toggleInput = document.createElement('input');
                toggleInput.type = 'hidden';
                toggleInput.name = 'toggle_status';
                toggleInput.value = '1';
                
                form.appendChild(userIdInput);
                form.appendChild(actionInput);
                form.appendChild(toggleInput);
                document.body.appendChild(form);
                form.submit();
            }
        }
        
        function deactivateUser(userId, email) {
            if (confirm(`هل تريد تعطيل حساب ${email}؟`)) {
                const form = document.createElement('form');
                form.method = 'POST';
                form.style.display = 'none';
                
                const userIdInput = document.createElement('input');
                userIdInput.type = 'hidden';
                userIdInput.name = 'user_id';
                userIdInput.value = userId;
                
                const actionInput = document.createElement('input');
                actionInput.type = 'hidden';
                actionInput.name = 'action';
                actionInput.value = 'deactivate';
                
                const toggleInput = document.createElement('input');
                toggleInput.type = 'hidden';
                toggleInput.name = 'toggle_status';
                toggleInput.value = '1';
                
                form.appendChild(userIdInput);
                form.appendChild(actionInput);
                form.appendChild(toggleInput);
                document.body.appendChild(form);
                form.submit();
            }
        }
        
        function resetPassword(userId, email) {
            if (confirm(`هل تريد إعادة تعيين كلمة مرور ${email}؟\nسيتم إنشاء كلمة مرور مؤقتة جديدة.`)) {
                const form = document.createElement('form');
                form.method = 'POST';
                form.style.display = 'none';
                
                const userIdInput = document.createElement('input');
                userIdInput.type = 'hidden';
                userIdInput.name = 'user_id';
                userIdInput.value = userId;
                
                const resetInput = document.createElement('input');
                resetInput.type = 'hidden';
                resetInput.name = 'reset_password';
                resetInput.value = '1';
                
                form.appendChild(userIdInput);
                form.appendChild(resetInput);
                document.body.appendChild(form);
                form.submit();
            }
        }
        
        function deleteUser(userId, email) {
            if (confirm(`⚠️ تحذير: هذا الإجراء لا يمكن التراجع عنه!\nهل أنت متأكد من حذف حساب ${email}؟`)) {
                const form = document.createElement('form');
                form.method = 'POST';
                form.style.display = 'none';
                
                const userIdInput = document.createElement('input');
                userIdInput.type = 'hidden';
                userIdInput.name = 'user_id';
                userIdInput.value = userId;
                
                const deleteInput = document.createElement('input');
                deleteInput.type = 'hidden';
                deleteInput.name = 'delete_user';
                deleteInput.value = '1';
                
                form.appendChild(userIdInput);
                form.appendChild(deleteInput);
                document.body.appendChild(form);
                form.submit();
            }
        }
        
        // نسخ كلمة المرور
        function copyPassword() {
            const password = document.getElementById('tempPassword').textContent;
            navigator.clipboard.writeText(password).then(() => {
                const btn = document.querySelector('.copy-btn');
                btn.innerHTML = '<i class="fas fa-check"></i> تم النسخ!';
                btn.classList.add('copied');
                setTimeout(() => {
                    btn.innerHTML = '<i class="fas fa-copy"></i> نسخ إلى الحافظة';
                    btn.classList.remove('copied');
                }, 2000);
            });
        }
        
        // فتح وإغلاق النماذج
        function openModal(modalId) {
            document.getElementById(modalId).style.display = 'flex';
        }
        
        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
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
        
        // توليد كلمة مرور عشوائية
        function generatePassword() {
            const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
            let password = '';
            for (let i = 0; i < 12; i++) {
                password += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            document.querySelector('input[name="password"]').value = password;
        }
        
        // تفعيل توليد كلمة المرور عند تحميل الصفحة
        document.addEventListener('DOMContentLoaded', function() {
            const generateBtn = document.createElement('button');
            generateBtn.type = 'button';
            generateBtn.className = 'btn btn-secondary btn-sm';
            generateBtn.innerHTML = '<i class="fas fa-redo"></i> توليد';
            generateBtn.onclick = generatePassword;
            
            const passwordField = document.querySelector('input[name="password"]');
            passwordField.parentNode.insertBefore(generateBtn, passwordField.nextSibling);
        });
    </script>
</body>
</html>