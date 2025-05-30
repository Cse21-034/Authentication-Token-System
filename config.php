<?php
// Database connection details
$host = 'sql306.infinityfree.com';
$dbname = 'if0_38044623_Jwt_token';
$username = 'if0_38044623';
$password = 'yfnOOQrdy2Kj';
$port = '3306';

// Database connection
try {
    $pdo = new PDO("mysql:host=$host;port=$port;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

// JWT configuration
define('JWT_SECRET', 'b9f2836c79fc45129f8b2f9ae4894dcb6823fa83f4a340aa6c7e4f07fd3b8ea2'); // Example key
define('JWT_ISSUER', 'AuthTokenSystem');
define('JWT_ALGORITHM', 'HS256');
define('JWT_EXPIRATION_MINUTES', 60); // 1 hour
?>
