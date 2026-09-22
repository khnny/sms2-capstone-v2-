<?php
declare(strict_types=1);

require_once __DIR__ . '/../../../config/config.php';
require_once ROOT_PATH . '/includes/authentication.php';
require_once ROOT_PATH . '/modules/crad/config/config.php';
require_once ROOT_PATH . '/modules/crad/includes/research-services-clearance.php';
require_once ROOT_PATH . '/modules/crad/includes/research-clearance-payment.php';

requireAuth();

$crad = rscDb();
$paymentId = (int) ($_GET['id'] ?? 0);
if (!$crad instanceof PDO || $paymentId <= 0) {
    http_response_code(404);
    exit('File not found.');
}

$payment = rcpFindById($crad, $paymentId);
if (!$payment) {
    http_response_code(404);
    exit('File not found.');
}

$role = getCurrentUserRoleKey();
$allowed = rcpCanApprove();
if ($role === 'student') {
    $group = chapterRegisteredStudentGroup($crad);
    $allowed = $group && (int) $group['id'] === (int) ($payment['research_group_id'] ?? 0);
}
if (!$allowed) {
    http_response_code(403);
    exit('Access denied.');
}

$file = basename(str_replace('\\', '/', (string) ($payment['uploaded_file'] ?? '')));
if ($file === '' || $file === '.' || $file === '..') {
    http_response_code(404);
    exit('File not found.');
}

$path = rcpPaymentImagePath($file);
if ($path === null) {
    http_response_code(404);
    exit('File not found.');
}

$info = @getimagesize($path);
$mime = strtolower((string) ($info['mime'] ?? ''));
$allowedMimes = ['image/png' => 'png', 'image/jpeg' => 'jpg'];
if (!isset($allowedMimes[$mime])) {
    http_response_code(415);
    exit('Unsupported file type.');
}

header('Content-Type: ' . $mime);
header('Content-Length: ' . (string) filesize($path));
header('Content-Disposition: inline; filename="payment.' . $allowedMimes[$mime] . '"');
header('Cache-Control: private, no-store, max-age=0');
header('X-Content-Type-Options: nosniff');
readfile($path);
exit;