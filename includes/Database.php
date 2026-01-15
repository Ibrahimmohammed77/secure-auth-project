<?php
class Database {
    private static $instance = null;
    private $connection;
    
    private function __construct() {
        $config = require __DIR__ . '/../config/config.php';
        
        try {
            $dsn = "mysql:host={$config['database']['host']};dbname={$config['database']['name']};charset={$config['database']['charset']}";
            
            $this->connection = new PDO($dsn, 
                $config['database']['username'], 
                $config['database']['password'],
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false,
                    PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
                ]
            );
            
        } catch (PDOException $e) {
            die("فشل الاتصال بقاعدة البيانات: " . $e->getMessage());
        }
    }
    
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new Database();
        }
        return self::$instance->connection;
    }
    
    public static function createTables() {
        $pdo = self::getInstance();
        
        $sql = "
        -- جدول المستخدمين
        CREATE TABLE IF NOT EXISTS users (
            id INT PRIMARY KEY AUTO_INCREMENT,
            uuid CHAR(36) NOT NULL UNIQUE DEFAULT (UUID()),
            email VARCHAR(255) NOT NULL UNIQUE,
            username VARCHAR(50) UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            role ENUM('student', 'teacher', 'admin') DEFAULT 'student',
            is_active BOOLEAN DEFAULT TRUE,
            mfa_enabled BOOLEAN DEFAULT FALSE,
            mfa_secret VARCHAR(32),
            mfa_backup_codes JSON,
            failed_login_attempts INT DEFAULT 0,
            account_locked_until DATETIME,
            last_login_at DATETIME,
            last_password_change DATETIME DEFAULT CURRENT_TIMESTAMP,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_email (email),
            INDEX idx_role (role),
            INDEX idx_active (is_active)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

        -- جدول جلسات آمن
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INT PRIMARY KEY AUTO_INCREMENT,
            user_id INT NOT NULL,
            session_token CHAR(64) NOT NULL UNIQUE,
            ip_address VARCHAR(45),
            user_agent TEXT,
            device_fingerprint VARCHAR(64),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            is_revoked BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_token (session_token),
            INDEX idx_user (user_id),
            INDEX idx_expires (expires_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

        -- جدول محاولات الدخول
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INT PRIMARY KEY AUTO_INCREMENT,
            email VARCHAR(255) NOT NULL,
            ip_address VARCHAR(45) NOT NULL,
            user_agent TEXT,
            attempt_status ENUM('success', 'wrong_password', 'account_locked', 'mfa_failed'),
            attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_email (email),
            INDEX idx_ip (ip_address),
            INDEX idx_time (attempted_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

        -- جدول رموز إعادة التعيين
        CREATE TABLE IF NOT EXISTS password_resets (
            id INT PRIMARY KEY AUTO_INCREMENT,
            user_id INT NOT NULL,
            reset_token CHAR(64) NOT NULL UNIQUE,
            requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            used_at DATETIME,
            ip_address VARCHAR(45),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_token (reset_token),
            INDEX idx_user (user_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

        -- جدول سجل الأحداث
        CREATE TABLE IF NOT EXISTS security_logs (
            id INT PRIMARY KEY AUTO_INCREMENT,
            user_id INT,
            action_type VARCHAR(50) NOT NULL,
            description TEXT,
            ip_address VARCHAR(45),
            user_agent TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
            INDEX idx_action (action_type),
            INDEX idx_user (user_id),
            INDEX idx_created (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        ";
        
        try {
            $pdo->exec($sql);
            return true;
        } catch (PDOException $e) {
            die("فشل إنشاء الجداول: " . $e->getMessage());
        }
    }
}
?>