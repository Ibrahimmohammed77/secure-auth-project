<?php
// ملف إعداد قاعدة البيانات
require_once 'includes/Database.php';

echo "بدأ إعداد قاعدة البيانات...\n";

try {
    // إنشاء الجداول
    Database::createTables();
    
    echo "✅ تم إنشاء الجداول بنجاح\n";
    
    // إضافة مستخدم تجريبي
    $pdo = Database::getInstance();
    
    // مستخدم طالب
    $studentPassword = password_hash('Student@123', PASSWORD_BCRYPT, ['cost' => 12]);
    $stmt = $pdo->prepare("INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'student')");
    $stmt->execute(['student@example.com', $studentPassword]);
    
    // مستخدم مدرس
    $teacherPassword = password_hash('Teacher@123', PASSWORD_BCRYPT, ['cost' => 12]);
    $stmt = $pdo->prepare("INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'teacher')");
    $stmt->execute(['teacher@example.com', $teacherPassword]);
    
    // مستخدم مدير
    $adminPassword = password_hash('Admin@123', PASSWORD_BCRYPT, ['cost' => 12]);
    $stmt = $pdo->prepare("INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'admin')");
    $stmt->execute(['admin@example.com', $adminPassword]);
    
    echo "✅ تم إنشاء المستخدمين التجريبيين:\n";
    echo "   👨‍🎓 طالب: student@example.com / Student@123\n";
    echo "   👨‍🏫 مدرس: teacher@example.com / Teacher@123\n";
    echo "   👑 مدير: admin@example.com / Admin@123\n\n";
    
    echo "🎉 تم إعداد النظام بنجاح!\n";
    echo "يمكنك الآن:\n";
    echo "1. زيارة http://localhost/secure-auth-project\n";
    echo "2. تسجيل الدخول باستخدام أي من الحسابات أعلاه\n";
    echo "3. تشغيل الاختبارات: php tests/brute-force-test.php\n";
    
} catch (Exception $e) {
    echo "❌ حدث خطأ: " . $e->getMessage() . "\n";
}
?>