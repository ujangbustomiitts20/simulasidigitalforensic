<?php
/**
 * Logout Page
 * PT. TechMart Indonesia
 */
session_start();

// Log logout
$log_time = date('Y-m-d H:i:s');
$log_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$user = $_SESSION['user'] ?? 'unknown';
error_log("[$log_time] LOGOUT | IP: $log_ip | User: $user");

// Destroy session
$_SESSION = array();
session_destroy();

// Redirect to login
header('Location: login.php');
exit;
?>
