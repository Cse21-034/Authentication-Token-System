<?php
session_start();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Token System</title>
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
                    <?php if(isset($_SESSION['user_id'])): ?>
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
                    <?php else: ?>
                        <li class="nav-item">
                            <a class="nav-link" href="login.php">Login</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="register.php">Register</a>
                        </li>
                    <?php endif; ?>
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
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-10">
                    <div class="card bg-dark shadow-lg">
                        <div class="card-body p-5">
                            <h1 class="text-center mb-4">Authentication Token System</h1>
                            
                            <div class="row mb-5">
                                <div class="col-lg-6">
                                    <div class="p-4 bg-dark rounded border border-secondary mb-3">
                                        <h3><i class="fas fa-shield-alt text-primary"></i> Secure Token Authentication</h3>
                                        <p>Our system provides secure authentication using encrypted JWT tokens that can't be forged or modified.</p>
                                    </div>
                                </div>
                                <div class="col-lg-6">
                                    <div class="p-4 bg-dark rounded border border-secondary mb-3">
                                        <h3><i class="fas fa-users text-success"></i> User Access Management</h3>
                                        <p>Control access levels with role-based permissions embedded directly in authentication tokens.</p>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="section">
                                <h2>About the System</h2>
                                <p>
                                    This authentication token system provides a secure way for users to authenticate and access 
                                    multiple related systems with a single sign-on. The token contains information about the user,
                                    their permissions, when the token was issued, and when it expires.
                                </p>
                                <p>
                                    The token is secured using industry-standard encryption and digital signatures to prevent forgery
                                    or modification, ensuring that only genuine users can access protected resources.
                                </p>
                            </div>

                            <div class="section">
                                <h2>Key Features</h2>
                                <ul>
                                    <li>Secure user registration and login</li>
                                    <li>JWT-based authentication tokens</li>
                                    <li>Role-based access control</li>
                                    <li>Token validation and verification</li>
                                    <li>Token revocation</li>
                                </ul>
                            </div>

                            <div class="section text-center">
                                <?php if(isset($_SESSION['user_id'])): ?>
                                    <a href="dashboard.php" class="btn btn-primary btn-lg">
                                        <i class="fas fa-user-shield"></i> Access Your Dashboard
                                    </a>
                                <?php else: ?>
                                    <div class="d-grid gap-3 d-md-flex justify-content-md-center">
                                        <a href="login.php" class="btn btn-primary btn-lg">
                                            <i class="fas fa-sign-in-alt"></i> Login
                                        </a>
                                        <a href="register.php" class="btn btn-secondary btn-lg">
                                            <i class="fas fa-user-plus"></i> Register
                                        </a>
                                    </div>
                                <?php endif; ?>
                            </div>
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