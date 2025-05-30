<?php
// JWT Helper Functions
// Implementation of JWT (JSON Web Token) for our authentication system

/**
 * Generate a JWT token for a user
 * 
 * @param array $user User data array with id, username, role
 * @param int $expiration_minutes Token validity period in minutes
 * @return string Encoded JWT token
 */
function generate_token($user, $expiration_minutes = JWT_EXPIRATION_MINUTES) {
    // Get the current time
    $issued_at = time();
    $expires_at = $issued_at + ($expiration_minutes * 60);
    
    // Create unique token ID
    $jti = bin2hex(random_bytes(16)); // Creates a UUID-like identifier
    
    // Create header
    $header = [
        'alg' => JWT_ALGORITHM,
        'typ' => 'JWT'
    ];
    
    // Create payload
    $payload = [
        'sub' => $user['id'],          // Subject (user ID)
        'iat' => $issued_at,           // Issued at time
        'exp' => $expires_at,          // Expiration time
        'jti' => $jti,                 // JWT ID (unique identifier)
        'iss' => JWT_ISSUER,           // Issuer (system name)
        'username' => $user['username'],// Username
        'role' => $user['role'],       // User's role/permissions
    ];
    
    // Encode header and payload
    $base64UrlHeader = base64url_encode(json_encode($header));
    $base64UrlPayload = base64url_encode(json_encode($payload));
    
    // Create signature
    $signature = hash_hmac('sha256', "$base64UrlHeader.$base64UrlPayload", JWT_SECRET, true);
    $base64UrlSignature = base64url_encode($signature);
    
    // Create token
    $jwt = "$base64UrlHeader.$base64UrlPayload.$base64UrlSignature";
    
    return $jwt;
}

/**
 * Validate a JWT token and return the payload if valid
 * 
 * @param string $token JWT token string
 * @return array|null Token payload if valid, null if invalid
 */
function validate_token($token) {
    global $pdo;
    
    // Split token into parts
    $tokenParts = explode('.', $token);
    if (count($tokenParts) != 3) {
        return null; // Not a valid JWT format
    }
    
    list($base64UrlHeader, $base64UrlPayload, $base64UrlSignature) = $tokenParts;
    
    // Verify signature
    $signature = base64url_decode($base64UrlSignature);
    $expectedSignature = hash_hmac('sha256', "$base64UrlHeader.$base64UrlPayload", JWT_SECRET, true);
    
    if (!hash_equals($signature, $expectedSignature)) {
        return null; // Invalid signature
    }
    
    // Decode payload
    $payload = json_decode(base64url_decode($base64UrlPayload), true);
    
    // Check if token is expired
    if (isset($payload['exp']) && $payload['exp'] < time()) {
        return null; // Token expired
    }
    
    // Check if token is blacklisted
    if (isset($payload['jti'])) {
        $stmt = $pdo->prepare("SELECT id FROM token_blacklist WHERE jti = :jti");
        $stmt->execute(['jti' => $payload['jti']]);
        
        if ($stmt->rowCount() > 0) {
            return null; // Token is blacklisted
        }
    }
    
    return $payload;
}



function decode_token_without_blacklist($token) {
    // Split token
    $tokenParts = explode('.', $token);
    if (count($tokenParts) !== 3) {
        return null;
    }

    list($header, $payload, $signature) = $tokenParts;

    // Check signature
    $expectedSig = hash_hmac('sha256', "$header.$payload", JWT_SECRET, true);
    if (!hash_equals(base64url_decode($signature), $expectedSig)) {
        return null;
    }

    // Decode payload
    $data = json_decode(base64url_decode($payload), true);

    // Check expiration
    if (isset($data['exp']) && $data['exp'] < time()) {
        return null;
    }

    return $data;
}


/**
 * Blacklist a token to prevent reuse
 * 
 * @param string $token JWT token string
 * @return bool True if blacklisted successfully, false otherwise
 */
function blacklist_token($token) {
    global $pdo;

    // Step 1: Split token
    $tokenParts = explode('.', $token);
    if (count($tokenParts) != 3) {
        error_log("❌ Token does not have 3 parts.");
        return false;
    }

    list($base64UrlHeader, $base64UrlPayload, $base64UrlSignature) = $tokenParts;

    // Step 2: Decode payload
    $payload = json_decode(base64url_decode($base64UrlPayload), true);
    if (!isset($payload['jti']) || !isset($payload['exp'])) {
        error_log("❌ Token missing jti or exp.");
        return false;
    }

    // Step 3: Check if already blacklisted
    $stmt = $pdo->prepare("SELECT id FROM token_blacklist WHERE jti = :jti");
    $stmt->execute(['jti' => $payload['jti']]);

    if ($stmt->rowCount() > 0) {
        error_log("ℹ️ Token already blacklisted.");
        return true;
    }

    // Step 4: Insert into blacklist
    try {
        $stmt = $pdo->prepare("INSERT INTO token_blacklist (jti, expires_at) VALUES (:jti, FROM_UNIXTIME(:expires_at))");
        $stmt->execute([
            'jti' => $payload['jti'],
            'expires_at' => $payload['exp']
        ]);
        error_log("✅ Token blacklisted: " . $payload['jti']);
        return true;
    } catch (PDOException $e) {
        error_log("❌ DB Insert Error: " . $e->getMessage());
        return false;
    }
}

/**
 * Clean expired tokens from the blacklist
 * 
 * @return bool True if cleaned successfully, false otherwise
 */
function clean_blacklist() {
    global $pdo;
    
    try {
        $stmt = $pdo->prepare("DELETE FROM token_blacklist WHERE expires_at < CURRENT_TIMESTAMP");
        $stmt->execute();
        
        return true;
    } catch (PDOException $e) {
        error_log("Error cleaning blacklist: " . $e->getMessage());
        return false;
    }
}

/**
 * Base64Url encode a string
 * 
 * @param string $data Data to encode
 * @return string Base64Url encoded string
 */
function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

/**
 * Base64Url decode a string
 * 
 * @param string $data Data to decode
 * @return string Decoded data
 */
function base64url_decode($data) {
    return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', 3 - (3 + strlen($data)) % 4));
}

/**
 * Sanitize user input to prevent common injection attacks
 * 
 * @param string $input_str String to sanitize
 * @return string Sanitized string
 */
function sanitize_input($input_str) {
    if (!$input_str) {
        return $input_str;
    }
    
    // Replace potentially dangerous characters
    $dangerous_chars = [
        '<' => '&lt;',
        '>' => '&gt;',
        '"' => '&quot;',
        "'" => '&#x27;',
        '/' => '&#x2F;',
        '\\' => '&#x5C;',
        '&' => '&amp;',
        ';' => '&#x3B;'
    ];
    
    return str_replace(array_keys($dangerous_chars), array_values($dangerous_chars), $input_str);
}
?>