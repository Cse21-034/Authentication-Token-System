<?php
session_start();
require_once 'config.php';
require_once 'jwt_helper.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    $_SESSION['message'] = 'Please login to access this page.';
    $_SESSION['message_type'] = 'warning';
    $_SESSION['redirect_url'] = $_SERVER['REQUEST_URI'];
    header('Location: login.php');
    exit;
}

$token = '';
$payload = null;
$is_valid = false;

// Process token verification
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['token'] ?? '';
    
    if (empty($token)) {
        $_SESSION['message'] = 'Token is required';
        $_SESSION['message_type'] = 'danger';
    } else {
        // Validate token
        $payload = validate_token($token);
        $is_valid = ($payload !== null);
        
        if ($is_valid) {
            $_SESSION['message'] = 'Token is valid!';
            $_SESSION['message_type'] = 'success';
        } else {
            $_SESSION['message'] = 'Token is invalid or expired!';
            $_SESSION['message_type'] = 'danger';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Token - Authentication Token System</title>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <!-- Custom CSS -->
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="index.php">
                <i class="fas fa-lock"></i> Auth Token System
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" 
                    aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="index.php">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="dashboard.php">Dashboard</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" href="verify_token.php">Verify Token</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="logout.php">Logout</a>
                    </li>
                    <li class="nav-item">
                        <span class="nav-link">
                            <i class="fas fa-user"></i> <?php echo htmlspecialchars($_SESSION['username']); ?>
                            <span class="badge bg-secondary user-role"><?php echo htmlspecialchars($_SESSION['role']); ?></span>
                        </span>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <!-- Flash Messages -->
    <div class="container mt-3">
        <?php if(isset($_SESSION['message'])): ?>
            <div class="alert alert-<?php echo $_SESSION['message_type']; ?> alert-dismissible fade show" role="alert">
                <?php 
                    echo $_SESSION['message']; 
                    unset($_SESSION['message']);
                    unset($_SESSION['message_type']);
                ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        <?php endif; ?>
    </div>

    <!-- Main Content -->
    <main class="container my-4">
        <div class="row">
            <div class="col-lg-12">
                <div class="card bg-dark">
                    <div class="card-header bg-dark">
                        <h2><i class="fas fa-check-circle"></i> Verify Token</h2>
                    </div>
                    <div class="card-body">
                        <div class="section">
                            <p>Enter a token below to verify its validity and view its contents.</p>
                            
                            <form method="POST" action="verify_token.php" id="verify-token-form">
                                <div class="mb-3">
                                    <label for="token-input" class="form-label">Token</label>
                                    <textarea class="form-control token-textarea" id="token-input" name="token" rows="5" 
                                              placeholder="Paste the token to verify"><?php echo htmlspecialchars($token); ?></textarea>
                                </div>
                                
                                <div class="mb-4">
                                    <button type="submit" class="btn btn-primary">Verify Token</button>
                                    <a href="dashboard.php" class="btn btn-secondary">
                                        <i class="fas fa-arrow-left"></i> Back to Dashboard
                                    </a>
                                </div>
                            </form>
                        </div>
                        
                        <div id="token-verification-result">
                            <?php if ($payload): ?>
                                <div class="section">
                                    <h3>Verification Result</h3>
                                    <div class="alert <?php echo $is_valid ? 'alert-success' : 'alert-danger'; ?>">
                                        <?php if ($is_valid): ?>
                                            <i class="fas fa-check-circle"></i> <strong>Valid Token</strong> - This token is authentic and has not been tampered with.
                                        <?php else: ?>
                                            <i class="fas fa-times-circle"></i> <strong>Invalid Token</strong> - This token is invalid, has been tampered with, or has expired.
                                        <?php endif; ?>
                                    </div>
                                </div>
                                
                                <?php if ($is_valid): ?>
                                    <div class="section">
                                        <h3><i class="fas fa-list"></i> Token Contents</h3>
                                        <div class="token-payload">
                                            <?php foreach($payload as $key => $value): ?>
                                                <div class="payload-item">
                                                    <span class="payload-key"><?php echo htmlspecialchars($key); ?>:</span>
                                                    <span class="payload-value">
                                                        <?php 
                                                        if ($key === 'exp' || $key === 'iat') {
                                                            echo date('Y-m-d H:i:s', $value);
                                                        } else {
                                                            echo htmlspecialchars(is_string($value) ? $value : json_encode($value));
                                                        }
                                                        ?>
                                                    </span>
                                                </div>
                                            <?php endforeach; ?>
                                        </div>
                                    </div>
                                    
                                    <div class="section">
                                        <h3><i class="fas fa-user"></i> User Information</h3>
                                        <ul>
                                            <li><strong>User ID:</strong> <?php echo htmlspecialchars($payload['sub']); ?></li>
                                            <li><strong>Username:</strong> <?php echo htmlspecialchars($payload['username']); ?></li>
                                            <li><strong>Role:</strong> <?php echo htmlspecialchars($payload['role']); ?></li>
                                        </ul>
                                    </div>
                                    
                                    <div class="section">
                                        <h3><i class="fas fa-shield-alt"></i> Token Security Information</h3>
                                        <ul>
                                            <li><strong>Issuer:</strong> <?php echo htmlspecialchars($payload['iss']); ?></li>
                                            <li><strong>Issued At:</strong> <?php echo date('Y-m-d H:i:s', $payload['iat']); ?></li>
                                            <li><strong>Expires At:</strong> <?php echo date('Y-m-d H:i:s', $payload['exp']); ?></li>
                                            <li><strong>Token ID:</strong> <?php echo htmlspecialchars($payload['jti']); ?></li>
                                        </ul>
                                    </div>
                                <?php endif; ?>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <!-- Footer -->
    <footer class="bg-dark text-light py-4">
        <div class="container">
            <div class="row">
                <div class="col-md-6">
                    <h5>Authentication Token System</h5>
                    <p>A secure authentication system using JWT tokens</p>
                </div>
                <div class="col-md-6 text-md-end">
                    <p>&copy; 2025 Auth Token System</p>
                </div>
            </div>
        </div>
    </footer>

    <!-- Bootstrap JS Bundle -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- Custom JavaScript -->
    <script src="js/main.js"></script>
</body>
</html>