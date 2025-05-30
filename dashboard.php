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
$token_error = null;
$payload = null;
$expirationTime = null;

if (!$token) {
    $token_error = 'No authentication token found. Please log in again.';
    setcookie('auth_token', '', time() - 3600, '/', '', true, true);
}
 
//$token = generate_token($user);

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Authentication Token System</title>
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
                        <a class="nav-link active" href="dashboard.php">Dashboard</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="verify_token.php">Verify Token</a>
                    </li>
                     <li class="nav-item">
                        <a class="nav-link" href="apps.php">Apps</a>
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
                        <h2><i class="fas fa-tachometer-alt"></i> Dashboard</h2>
                    </div>
                    <div class="card-body">
                     <?php if ($token_error): ?>

                     <div class="alert alert-danger">
                                <i class="fas fa-times-circle"></i> <?php echo $token_error; ?>
                            </div>
                        <?php else: ?>
                        
                        <div class="alert alert-info">
                            <h4 class="alert-heading"><i class="fas fa-info-circle"></i> Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h4>
                            <p>You are logged in as <strong><?php echo htmlspecialchars($_SESSION['role']); ?></strong>. From here you can manage your authentication tokens.</p>
                        </div>
                        
                        <div class="section">
                            <h3><i class="fas fa-key"></i> Your Authentication Token</h3>
                            <p>This is your current authentication token. It contains your identity and access level information.</p>
                            
                            <div class="token-container">
                                <textarea id="token-text" class="token-textarea" readonly><?php echo $token; ?></textarea>
                                <div class="token-actions">
                                    <button id="copy-token-btn" class="btn btn-outline-light">
                                        <i class="fa fa-copy"></i> Copy Token
                                    </button>
                                    <a href="token_info.php?token=<?php echo urlencode($token); ?>" class="btn btn-outline-info">
                                        <i class="fa fa-info-circle"></i> View Token Info
                                    </a>
                                    <button id="revoke-token-btn123" class="btn btn-outline-danger">
                                        <i class="fa fa-ban"></i> Revoke Token
                                    </button>
                                </div>
                            </div>
                            
                            <?php
                            // Get token expiration from payload
                            $tokenParts = explode('.', $token);
                            $payload = json_decode(base64url_decode($tokenParts[1]), true);
                            $expirationTime = $payload['exp'] ?? 0;
                            ?>
                            
                            <div class="alert alert-warning mt-3">
                                <i class="fas fa-exclamation-triangle"></i> This token will expire in 
                                <span id="token-expiration-time" data-exp-time="<?php echo $expirationTime; ?>">60 minutes</span>. 
                                After expiration, you'll need to return to the dashboard for a new token.
                            </div>
                        </div>
                        
                        <div class="section">
                            <h3><i class="fas fa-shield-alt"></i> Token Security Information</h3>
                            <p>Your authentication token includes the following security features:</p>
                            <ul>
                                <li><strong>Digital Signature:</strong> Prevents tampering and ensures authenticity</li>
                                <li><strong>Encryption:</strong> Protects sensitive information in the token</li>
                                <li><strong>Time-limited:</strong> Automatically expires after 60 minutes</li>
                                <li><strong>Revocable:</strong> Can be invalidated if compromised</li>
                            </ul>
                        </div>
                        
                        <div class="section">
                            <h3><i class="fas fa-cogs"></i> Token Actions</h3>
                            <div class="row g-4">
                                <div class="col-md-6">
                                    <div class="card h-100 bg-dark border-secondary">
                                        <div class="card-body">
                                            <h5 class="card-title"><i class="fas fa-search"></i> Verify a Token</h5>
                                            <p class="card-text">Check if a token is valid and view its contents</p>
                                            <a href="verify_token.php" class="btn btn-outline-primary">Verify Token</a>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="card h-100 bg-dark border-secondary">
                                        <div class="card-body">
                                            <h5 class="card-title"><i class="fas fa-sync-alt"></i> Generate New Token</h5>
                                            <p class="card-text">Refresh your current token with a new expiration time</p>
                                           <a href="refresh_token.php" class="btn btn-outline-success">Generate New Token</a>

                                        </div>
                                    </div>
                                </div>
                            </div>
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
    <script>
document.getElementById('revoke-token-btn123').addEventListener('click', function () {
    const token = document.getElementById('token-text').value;

    if (!token) {
        alert('Token not found.');
        return;
    }

    if (!confirm("Are you sure you want to revoke this token?")) {
        return;
    }

    fetch('api/revoke_token.php', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ token: token })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('✅ Token revoked successfully.');
            // Optional: Expire the cookie client-side
            document.cookie = "auth_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 UTC; Secure; HttpOnly; SameSite=Strict";
            location.reload(); // Refresh to reflect changes
        } else {
            alert('❌ Failed to revoke token: ' + data.message);
        }
    })
    .catch(error => {
        console.error('Error revoking token:', error);
        alert('An error occurred while revoking the token.');
    });
});
</script>


    <!-- Bootstrap JS Bundle -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- Custom JavaScript -->
    <script src="js/main.js"></script>
</body>
</html>