<?php
require_once 'config.php';

// Initialize secure session
initSecureSession();

// Set content type to JSON
header('Content-Type: application/json');

// Check if user is authenticated
if (!isAuthenticated()) {
    echo json_encode(['success' => false, 'message' => 'Not authenticated']);
    exit;
}

// Regenerate session ID for security
session_regenerate_id(true);
$_SESSION['last_regeneration'] = time();

// Log the session extension
$userId = $_SESSION['user_id'];
$username = $_SESSION['username'];
logSecurityEvent('authentication', 'info', "Session extended for user: $username", $userId, getClientIP());

// Return success response
echo json_encode(['success' => true]);
exit;
