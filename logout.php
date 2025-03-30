<?php
require_once 'config.php';

// Initialize secure session
initSecureSession();

// Get username before destroying session
$username = isset($_SESSION['username']) ? $_SESSION['username'] : 'Unknown';
$userId = isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null;

// Log the logout action
if ($userId) {
    logSecurityEvent('authentication', 'info', "User logged out: $username", $userId, getClientIP());
}

// Clear all session variables
$_SESSION = array();

// If it's desired to kill the session cookie, delete the session cookie
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// Destroy the session
session_destroy();

// Redirect to login page
header("Location: index.php");
exit;
