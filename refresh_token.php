<?php
session_start();
require_once 'config.php';
require_once 'jwt_helper.php';

// Get old token
$oldToken = $_COOKIE['auth_token'] ?? '';
if (!$oldToken) {
    $_SESSION['message'] = 'No existing token found.';
    $_SESSION['message_type'] = 'danger';
    header('Location: dashboard.php');
    exit;
}

// Validate the old token
$payload = decode_token_without_blacklist($oldToken);

if (!$payload) {
    $_SESSION['message'] = 'Invalid or expired token.';
    $_SESSION['message_type'] = 'danger';
    header('Location: dashboard.php');
    exit;
}

// OPTIONAL: blacklist old token
blacklist_token($oldToken);

// Generate a new token using user info from payload
$user = [
    'id' => $payload['sub'],
    'username' => $payload['username'],
    'role' => $payload['role']
];

$newToken = generate_token($user);

// Set new token in secure HttpOnly cookie
setcookie('auth_token', $newToken, [
    'expires' => time() + (JWT_EXPIRATION_MINUTES * 60),
    'path' => '/',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);

$_SESSION['message'] = 'A new token has been generated.';
$_SESSION['message_type'] = 'success';
header('Location: dashboard.php');
exit;
?>
