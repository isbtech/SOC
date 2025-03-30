<?php
// Database connection configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'socusrs');
define('DB_PASS', '00000');
define('DB_NAME', 'socdbs');

// Application constants
define('SITE_NAME', 'SecOps Center');
define('SITE_URL', 'https://cfsoc.baseurl.in/');
define('UPLOAD_DIR', 'uploads/');
define('LOG_DIR', 'logs/');

// Session configuration
define('SESSION_NAME', 'secops_session');
define('SESSION_LIFETIME', 3600); // 1 hour in seconds
define('SESSION_REGENERATE_TIME', 900); // Regenerate session ID every 15 minutes

// Security settings
define('PASSWORD_MIN_LENGTH', 6);
define('PASSWORD_REQUIRES_SPECIAL', true);
define('PASSWORD_REQUIRES_NUMBER', true);
define('PASSWORD_REQUIRES_UPPERCASE', true);
define('PASSWORD_REQUIRES_LOWERCASE', true);
define('ACCOUNT_LOCKOUT_THRESHOLD', 5); // Number of failed attempts before lockout
define('ACCOUNT_LOCKOUT_DURATION', 1800); // Lockout duration in seconds (30 minutes)
define('API_RATE_LIMIT', 100); // Requests per minute

// Timezone
date_default_timezone_set('UTC');

// Error reporting (disable on production)
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Create database connection
function connectDB() {
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    if ($conn->connect_error) {
        logError("Database connection failed: " . $conn->connect_error);
        die("Connection failed. Please contact the administrator.");
    }
    
    // Set charset to ensure proper encoding
    $conn->set_charset("utf8mb4");
    
    return $conn;
}

// Initialize secure session
function initSecureSession() {
    // Set secure session parameters
    ini_set('session.cookie_httponly', 1);
    ini_set('session.use_only_cookies', 1);
    
    // Use secure cookies in production environment
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
        ini_set('session.cookie_secure', 1);
    }
    
    // Set session name and lifetime
    session_name(SESSION_NAME);
    session_set_cookie_params(SESSION_LIFETIME);
    
    // Start the session
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    // Regenerate session ID periodically
    if (!isset($_SESSION['last_regeneration']) || 
        (time() - $_SESSION['last_regeneration']) > SESSION_REGENERATE_TIME) {
        session_regenerate_id(true);
        $_SESSION['last_regeneration'] = time();
    }
}

// Sanitize input data
function sanitizeInput($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $data;
}

// Log errors to file
function logError($message) {
    $timestamp = date('Y-m-d H:i:s');
    $logMessage = "[$timestamp] ERROR: $message" . PHP_EOL;
    
    if (!is_dir(LOG_DIR)) {
        mkdir(LOG_DIR, 0755, true);
    }
    
    file_put_contents(LOG_DIR . 'error.log', $logMessage, FILE_APPEND);
}

// Log security events to file and database
function logSecurityEvent($eventType, $severity, $description, $userId = null, $ipAddress = null) {
    // Log to file
    $timestamp = date('Y-m-d H:i:s');
    $logMessage = "[$timestamp] SECURITY EVENT: $eventType - $severity - $description";
    
    if ($userId) {
        $logMessage .= " - User ID: $userId";
    }
    
    if ($ipAddress) {
        $logMessage .= " - IP: $ipAddress";
    }
    
    $logMessage .= PHP_EOL;
    
    if (!is_dir(LOG_DIR)) {
        mkdir(LOG_DIR, 0755, true);
    }
    
    file_put_contents(LOG_DIR . 'security.log', $logMessage, FILE_APPEND);
    
    // Log to database
    $conn = connectDB();
    $userId = $userId ? (int)$userId : "NULL";
    $ipAddress = $ipAddress ? $conn->real_escape_string($ipAddress) : "NULL";
    $description = $conn->real_escape_string($description);
    $eventType = $conn->real_escape_string($eventType);
    $severity = $conn->real_escape_string($severity);
    
    $query = "INSERT INTO audit_logs (user_id, action_type, description, ip_address, user_agent) 
              VALUES ($userId, '$eventType', '$description', '$ipAddress', '{$_SERVER['HTTP_USER_AGENT']}')";
    
    $conn->query($query);
    $conn->close();
}

// Check if user is authenticated
function isAuthenticated() {
    return isset($_SESSION['user_id']) && isset($_SESSION['user_role']);
}

// Check if user has required role
function hasRole($requiredRole) {
    if (!isAuthenticated()) {
        return false;
    }
    
    $userRole = $_SESSION['user_role'];
    
    // Admin has access to everything
    if ($userRole === 'admin') {
        return true;
    }
    
    // Role-based access control
    switch ($requiredRole) {
        case 'admin':
            return $userRole === 'admin';
        case 'manager':
            return in_array($userRole, ['admin', 'manager']);
        case 'analyst':
            return in_array($userRole, ['admin', 'manager', 'analyst']);
        case 'viewer':
            return in_array($userRole, ['admin', 'manager', 'analyst', 'viewer']);
        default:
            return false;
    }
}

// Handle CSRF protection
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    if (!isset($_SESSION['csrf_token']) || $token !== $_SESSION['csrf_token']) {
        logSecurityEvent('security', 'high', 'CSRF token validation failed', 
                         isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null, 
                         $_SERVER['REMOTE_ADDR']);
        return false;
    }
    
    return true;
}

// Get client IP address
function getClientIP() {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        return $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        return $_SERVER['REMOTE_ADDR'];
    }
}
