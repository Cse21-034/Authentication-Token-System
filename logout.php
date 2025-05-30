<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();

// ✅ Include the JWT helper that defines blacklist_token()
require_once 'jwt_helper.php';
require_once 'config.php'; // in case your DB connection or constants are needed

// Optional: blacklist the token
$token = $_COOKIE['auth_token'] ?? '';
if ($token) {
    blacklist_token($token); // Revoke token by jti
}

// Clear all session variables
$_SESSION = [];

// Expire the auth_token cookie
setcookie('auth_token', '', time() - 3600, '/', '', true, true);

// Destroy the session properly
session_destroy();

// Start a fresh session for flash message (do this AFTER destroying the old session)
session_start();
$_SESSION['message'] = 'You have been logged out.';
$_SESSION['message_type'] = 'info';

header('Location: index.php');
exit;
?>
