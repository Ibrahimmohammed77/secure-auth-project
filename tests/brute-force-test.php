<?php
require_once '../includes/Auth.php';

class BruteForceTest {
    private $auth;
    private $testEmail = "test@example.com";
    
    public function __construct() {
        $this->auth = new Auth();
    }
    
    public function runTest() {
        echo "=== اختبار مقاومة هجمات Brute Force ===\n\n";
        
        $attempts = 0;
        $successfulBlock = false;
        $startTime = microtime(true);
        
        for ($i = 1; $i <= 15; $i++) {
            $attempts++;
            $password = "wrong_password_" . rand(1000, 9999);
            
            $attemptStart = microtime(true);
            $result = $this->auth->login($this->testEmail, $password);
            $attemptEnd = microtime(true);
            
            $responseTime = round($attemptEnd - $attemptStart, 2);
            
            echo "المحاولة {$i}:\n";
            echo "  - النتيجة: " . ($result['success'] ? '✅ نجاح' : '❌ فشل') . "\n";
            echo "  - الرسالة: " . ($result['message'] ?? 'N/A') . "\n";
            echo "  - وقت الاستجابة: {$responseTime} ثانية\n";
            
            if (isset($result['locked_until'])) {
                echo "  ⚠️  الحساب مقفل حتى: " . $result['locked_until'] . "\n";
                $successfulBlock = true;
                break;
            }
            
            if ($responseTime > 1) {
                echo "  ⏱️  تأخير مضاف (مقاومة للـBrute Force)\n";
            }
            
            echo "\n";
            
            // فاصل بين المحاولات
            if ($i % 5 === 0) {
                sleep(1);
            }
        }
        
        $totalTime = round(microtime(true) - $startTime, 2);
        
        echo "\n=== ملخص الاختبار ===\n";
        echo "عدد المحاولات: {$attempts}\n";
        echo "الوقت الإجمالي: {$totalTime} ثانية\n";
        
        if ($successfulBlock) {
            echo "✅ النتيجة: النظام يقاوم هجمات Brute Force بنجاح\n";
        } else {
            echo "❌ النتيجة: النظام يحتاج تحسينات في مقاومة هجمات Brute Force\n";
        }
        
        return $successfulBlock;
    }
    
    public function testRateLimiting() {
        echo "\n=== اختبار Rate Limiting ===\n\n";
        
        $ips = ['192.168.1.1', '192.168.1.2', '192.168.1.3'];
        $results = [];
        
        foreach ($ips as $ip) {
            $_SERVER['REMOTE_ADDR'] = $ip;
            
            // محاكاة 15 محاولة فاشلة
            for ($i = 1; $i <= 15; $i++) {
                $result = $this->auth->login('test@attack.com', 'wrong_password');
            }
            
            $results[$ip] = $this->auth->isIpRateLimited();
            echo "IP {$ip}: " . ($results[$ip] ? 'مقيد ⚠️' : 'غير مقيد ✅') . "\n";
        }
        
        $blockedCount = count(array_filter($results));
        echo "\nعدد IPs المقيدة: {$blockedCount}/" . count($ips) . "\n";
        
        return $blockedCount > 0;
    }
}

// تشغيل الاختبار
if (php_sapi_name() === 'cli') {
    $test = new BruteForceTest();
    
    echo "🔍 بدء اختبارات الأمان...\n";
    echo str_repeat("=", 50) . "\n";
    
    $test1 = $test->runTest();
    $test2 = $test->testRateLimiting();
    
    echo "\n" . str_repeat("=", 50) . "\n";
    
    if ($test1 && $test2) {
        echo "🎉 جميع الاختبارات نجحت! النظام آمن.\n";
    } else {
        echo "⚠️  بعض الاختبارات فشلت. النظام يحتاج تحسينات.\n";
    }
} else {
    echo "هذا الاختبار مصمم للتشغيل من سطر الأوامر (CLI) فقط.";
}
?>