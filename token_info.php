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

$token = trim($_COOKIE['auth_token'] ?? '');

if (!$token) {
    echo "No token received.";
    exit;
}




// Get token from query string
//$token = $_GET['token'] ?? '';
 

$payload = null;
$is_valid = false;

// Validate token if provided
if (!empty($token)) {
    $payload = validate_token($token);
    $is_valid = ($payload !== null);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Token Information - Authentication Token System</title>
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
                        <a class="nav-link" href="verify_token.php">Verify Token</a>
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
                        <h2><i class="fas fa-info-circle"></i> Token Information</h2>
                    </div>
                    <div class="card-body">
                        <?php if ($token): ?>
                            <div class="alert <?php echo $is_valid ? 'alert-success' : 'alert-danger'; ?>">
                                <h4 class="alert-heading">
                                    <?php if ($is_valid): ?>
                                        <i class="fas fa-check-circle"></i> Valid Token
                                    <?php else: ?>
                                        <i class="fas fa-times-circle"></i> Invalid Token
                                    <?php endif; ?>
                                </h4>
                                <p>
                                    <?php if ($is_valid): ?>
                                        This token is valid and has not been tampered with.
                                    <?php else: ?>
                                        This token is invalid or has expired.
                                    <?php endif; ?>
                                </p>
                            </div>
                            
                            <div class="section">
                                <h3><i class="fas fa-key"></i> Token</h3>
                                <div class="token-container">
                                    <textarea class="token-textarea" readonly><?php echo htmlspecialchars($token); ?></textarea>
                                </div>
                            </div>
                            
                            <?php if ($payload): ?>
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
                                    <h3><i class="fas fa-shield-alt"></i> Security Information</h3>
                                    <ul>
                                        <li><strong>Issuer:</strong> <?php echo htmlspecialchars($payload['iss']); ?></li>
                                        <li><strong>Issued At:</strong> <?php echo date('Y-m-d H:i:s', $payload['iat']); ?></li>
                                        <li><strong>Expires At:</strong> <?php echo date('Y-m-d H:i:s', $payload['exp']); ?></li>
                                        <li><strong>Token ID:</strong> <?php echo htmlspecialchars($payload['jti']); ?></li>
                                    </ul>
                                </div>
                            <?php endif; ?>
                            
                            <div class="mt-4">
                                <a href="dashboard.php" class="btn btn-primary">
                                    <i class="fas fa-arrow-left"></i> Back to Dashboard
                                </a>
                            </div>
                        <?php else: ?>
                            <div class="alert alert-warning">
                                <h4 class="alert-heading"><i class="fas fa-exclamation-triangle"></i> No Token Provided</h4>
                                <p>No token was provided for inspection. Please go back to your dashboard to get your token.</p>
                            </div>
                            <div class="mt-4">
                                <a href="dashboard.php" class="btn btn-primary">
                                    <i class="fas fa-arrow-left"></i> Back to Dashboard
                                </a>
                            </div>
                        <?php endif; ?>
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