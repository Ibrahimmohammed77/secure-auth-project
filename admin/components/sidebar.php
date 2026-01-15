<!-- includes/components/sidebar.php -->


<aside class="sidebar">
    <div class="sidebar-header">
        <h1><i class="fas fa-shield-alt"></i> نظام الأمان</h1>
        <p>لوحة تحكم إدارة الأمان المتقدمة</p>
    </div>
    
    <div class="user-info">
        <div class="user-avatar">
            <?php echo strtoupper(substr($user['email'], 0, 1)); ?>
        </div>
        <div class="user-details">
            <h3><?php echo htmlspecialchars($user['email']); ?></h3>
            <span><i class="fas fa-user-shield"></i> مدير النظام</span>
        </div>
    </div>
    
    <nav class="nav-menu">
        <a href="../dashboard.php" class="nav-item <?php echo basename($_SERVER['PHP_SELF']) == 'dashboard.php' ? 'active' : ''; ?>">
            <i class="fas fa-home"></i>
            <span>الرئيسية</span>
        </a>
        <a href="security-dashboard.php" class="nav-item <?php echo basename($_SERVER['PHP_SELF']) == 'security-dashboard.php' ? 'active' : ''; ?>">
            <i class="fas fa-shield-alt"></i>
            <span>لوحة الأمان</span>
        </a>
        <a href="users.php" class="nav-item <?php echo basename($_SERVER['PHP_SELF']) == 'users.php' ? 'active' : ''; ?>">
            <i class="fas fa-users"></i>
            <span>إدارة المستخدمين</span>
        </a>
        <a href="reports.php" class="nav-item <?php echo basename($_SERVER['PHP_SELF']) == 'reports.php' ? 'active' : ''; ?>">
            <i class="fas fa-chart-bar"></i>
            <span>التقارير</span>
        </a>
        <a href="settings.php" class="nav-item <?php echo basename($_SERVER['PHP_SELF']) == 'settings.php' ? 'active' : ''; ?>">
            <i class="fas fa-cog"></i>
            <span>الإعدادات</span>
        </a>
        <a href="logs.php" class="nav-item <?php echo basename($_SERVER['PHP_SELF']) == 'logs.php' ? 'active' : ''; ?>">
            <i class="fas fa-clipboard-list"></i>
            <span>سجلات النظام</span>
        </a>
        <a href="alerts.php" class="nav-item <?php echo basename($_SERVER['PHP_SELF']) == 'alerts.php' ? 'active' : ''; ?>">
            <i class="fas fa-bell"></i>
            <span>التنبيهات</span>
            <span class="status-badge status-critical">3</span>
        </a>
        <a href="../logout.php" class="nav-item logout-btn">
            <i class="fas fa-sign-out-alt"></i>
            <span>تسجيل الخروج</span>
        </a>
    </nav>
</aside>