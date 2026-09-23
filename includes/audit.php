<?php
/**
 * SMS 2 - Activity / audit logging
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/security.php';

/**
 * Make the audit trail available on installations that predate the prefixed
 * schema migration. This is deliberately limited to the one independent
 * audit table; normal schema migrations remain the preferred deployment path.
 */
function smsActivityLogTableReady(?PDO $pdo = null): bool
{
    static $ready = null;
    if ($ready !== null) {
        return $ready;
    }

    $pdo = $pdo ?: db();
    if (!$pdo) {
        return $ready = false;
    }

    try {
        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS `sms2_activity_logs` (
                `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
                `user_id` int(10) UNSIGNED DEFAULT NULL,
                `user_name` varchar(150) DEFAULT NULL,
                `role_key` varchar(40) DEFAULT NULL,
                `action` varchar(40) NOT NULL,
                `module_key` varchar(60) DEFAULT NULL,
                `detail` varchar(500) NOT NULL,
                `ip_address` varchar(45) DEFAULT NULL,
                `user_agent` varchar(255) DEFAULT NULL,
                `created_at` datetime NOT NULL DEFAULT current_timestamp(),
                PRIMARY KEY (`id`),
                KEY `idx_logs_user` (`user_id`),
                KEY `idx_logs_action` (`action`),
                KEY `idx_logs_created` (`created_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );
        return $ready = true;
    } catch (Throwable $e) {
        error_log('SMS2 activity log table unavailable: ' . $e->getMessage());
        return $ready = false;
    }
}

/**
 * Write an audit log entry.
 */
function logActivity(
    string $action,
    string $detail,
    ?string $moduleKey = 'System',
    ?int $userId = null,
    ?string $userName = null,
    ?string $roleKey = null,
    bool $allowSessionFallback = true
): void {
    $pdo = db();
    if (!$pdo || !smsActivityLogTableReady($pdo)) {
        return;
    }

    if ($allowSessionFallback) {
        if ($userId === null && !empty($_SESSION['user_id'])) {
            $userId = (int) $_SESSION['user_id'];
        }
        if ($userName === null) {
            $userName = $_SESSION['user_name'] ?? null;
        }
        if ($roleKey === null) {
            $roleKey = $_SESSION['user_role_key'] ?? null;
        }
    }

    try {
        $stmt = $pdo->prepare(
            'INSERT INTO `sms2_activity_logs`
                (user_id, user_name, role_key, action, module_key, detail, ip_address, user_agent)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        );
        $ua = substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255);
        $stmt->execute([
            $userId,
            $userName !== null ? substr($userName, 0, 150) : null,
            $roleKey !== null ? substr($roleKey, 0, 40) : null,
            substr($action, 0, 40),
            $moduleKey !== null ? substr($moduleKey, 0, 60) : null,
            substr($detail, 0, 500),
            smsClientIp(),
            $ua !== '' ? $ua : null,
        ]);
    } catch (Throwable $e) {
        error_log('SMS2 audit log failed: ' . $e->getMessage());
    }
}
