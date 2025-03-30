<?php
require_once 'config.php';

// Initialize secure session
initSecureSession();

// Redirect to dashboard if already logged in
if (isAuthenticated()) {
    header("Location: dashboard.php");
    exit;
}

// Handle login
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        $error = "Invalid request";
    } else {
        // Get and sanitize input
        $username = sanitizeInput($_POST['username']);
        $password = $_POST['password']; // Don't sanitize password
        
        if (empty($username) || empty($password)) {
            $error = "Username and password are required";
        } else {
            // Connect to database
            $conn = connectDB();
            
            // Check for account lockout
            $stmt = $conn->prepare("SELECT COUNT(*) as failed_attempts FROM audit_logs 
                                   WHERE action_type = 'failed_login' 
                                   AND description LIKE ? 
                                   AND timestamp > NOW() - INTERVAL ? SECOND");
            $descLike = "%username: $username%";
            $lockoutDuration = ACCOUNT_LOCKOUT_DURATION;
            $stmt->bind_param("si", $descLike, $lockoutDuration);
            $stmt->execute();
            $result = $stmt->get_result();
            $row = $result->fetch_assoc();
            
            if ($row['failed_attempts'] >= ACCOUNT_LOCKOUT_THRESHOLD) {
                $error = "Account temporarily locked due to multiple failed login attempts. Try again later.";
                logSecurityEvent('security', 'medium', "Login attempt on locked account: username: $username", 
                                null, getClientIP());
            } else {
                // Prepare statement to prevent SQL injection
                $stmt = $conn->prepare("SELECT user_id, username, password, role, is_active 
                                       FROM users WHERE username = ?");
                $stmt->bind_param("s", $username);
                $stmt->execute();
                $result = $stmt->get_result();
                
                if ($result->num_rows === 1) {
                    $user = $result->fetch_assoc();
                    
                    // Verify password
                    if (password_verify($password, $user['password'])) {
                        // Check if account is active
                        if ($user['is_active'] != 1) {
                            $error = "Account is disabled. Contact an administrator.";
                            logSecurityEvent('security', 'medium', "Login attempt on disabled account: username: $username", 
                                           null, getClientIP());
                        } else {
                            // Login successful
                            // Update last login time
                            $updateStmt = $conn->prepare("UPDATE users SET last_login = NOW() WHERE user_id = ?");
                            $updateStmt->bind_param("i", $user['user_id']);
                            $updateStmt->execute();
                            
                            // Set session variables
                            $_SESSION['user_id'] = $user['user_id'];
                            $_SESSION['username'] = $user['username'];
                            $_SESSION['user_role'] = $user['role'];
                            $_SESSION['login_time'] = time();
                            
                            // Log successful login
                            logSecurityEvent('authentication', 'info', "Successful login: username: $username", 
                                           $user['user_id'], getClientIP());
                            
                            // Redirect to dashboard
                            header("Location: dashboard.php");
                            exit;
                        }
                    } else {
                        // Password incorrect
                        $error = "Invalid username or password";
                        logSecurityEvent('security', 'medium', "Failed login attempt: username: $username, reason: invalid password", 
                                       null, getClientIP());
                    }
                } else {
                    // Username not found
                    $error = "Invalid username or password";
                    logSecurityEvent('security', 'medium', "Failed login attempt: username: $username, reason: username not found", 
                                   null, getClientIP());
                }
                
                // Close statement
                $stmt->close();
            }
            
            // Close connection
            $conn->close();
        }
    }
}

// Generate CSRF token for form
$csrfToken = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo SITE_NAME; ?> - Security Operations Center</title>
    <link rel="stylesheet" href="assets/css/style.css">
    <!-- Include modern UI framework CSS (Bootstrap, etc.) -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Include Font Awesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-light">
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-6">
                <div class="card shadow">
                    <div class="card-header bg-primary text-white text-center py-3">
                        <h2><i class="fas fa-shield-alt"></i> <?php echo SITE_NAME; ?></h2>
                        <p class="mb-0">Security Operations Center</p>
                    </div>
                    <div class="card-body p-4">
                        <?php if (!empty($error)): ?>
                            <div class="alert alert-danger" role="alert">
                                <i class="fas fa-exclamation-triangle"></i> <?php echo $error; ?>
                            </div>
                        <?php endif; ?>
                        
                        <form method="post" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                            
                            <div class="mb-3">
                                <label for="username" class="form-label"><i class="fas fa-user"></i> Username</label>
                                <input type="text" class="form-control" id="username" name="username" required autofocus>
                            </div>
                            
                            <div class="mb-3">
                                <label for="password" class="form-label"><i class="fas fa-lock"></i> Password</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            
                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary btn-lg">
                                    <i class="fas fa-sign-in-alt"></i> Login
                                </button>
                            </div>
                        </form>
                    </div>
                    <div class="card-footer text-center py-3">
                        <p class="text-muted mb-0">Authorized Access Only</p>
                        <small class="text-muted">All activities are monitored and logged</small>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Include JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="assets/js/main.js"></script>
</body>
</html>
