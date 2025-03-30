<?php
/**
 * Script for creating a new incident
 */
require_once 'config.php';

// Initialize secure session
initSecureSession();

// Check if user is authenticated and has proper permissions
if (!isAuthenticated() || !hasRole('admin', 'manager', 'analyst')) {
    header("Location: index.php");
    exit;
}

// Check if form was submitted
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: incidents.php");
    exit;
}

// Validate CSRF token
if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
    $_SESSION['error_message'] = "Invalid request";
    header("Location: incidents.php");
    exit;
}

// Get form data
$title = sanitizeInput($_POST['incident_title']);
$description = sanitizeInput($_POST['incident_description']);
$incidentType = sanitizeInput($_POST['incident_type']);
$severity = sanitizeInput($_POST['incident_severity']);
$assignTo = isset($_POST['assign_to']) && !empty($_POST['assign_to']) ? intval($_POST['assign_to']) : null;

// Connect to database
$conn = connectDB();

// Begin transaction
$conn->begin_transaction();

try {
    // Determine initial status
    $status = $assignTo ? 'assigned' : 'new';
    
    // Create new incident
    $stmt = $conn->prepare("INSERT INTO incidents (title, description, incident_type, severity, status, created_by, assigned_to, created_at, updated_at) 
                           VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())");
    $userId = $_SESSION['user_id'];
    $stmt->bind_param("sssssii", $title, $description, $incidentType, $severity, $status, $userId, $assignTo);
    $stmt->execute();
    
    // Get the new incident ID
    $incidentId = $conn->insert_id;
    
    // Add initial note
    $initialNote = "Incident created by " . $_SESSION['username'];
    $stmt = $conn->prepare("INSERT INTO incident_notes (incident_id, user_id, content, created_at) 
                           VALUES (?, ?, ?, NOW())");
    $stmt->bind_param("iis", $incidentId, $userId, $initialNote);
    $stmt->execute();
    
    // If the incident was created from an alert, link the alert's event
    if (isset($_POST['alert_id']) && is_numeric($_POST['alert_id'])) {
        $alertId = intval($_POST['alert_id']);
        
        // Get the event ID from the alert
        $stmt = $conn->prepare("SELECT event_id FROM alerts WHERE alert_id = ?");
        $stmt->bind_param("i", $alertId);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($row = $result->fetch_assoc()) {
            $eventId = $row['event_id'];
            
            // Link the event to the incident
            $stmt = $conn->prepare("INSERT INTO incident_events (incident_id, event_id, added_by, added_at) 
                                   VALUES (?, ?, ?, NOW())");
            $stmt->bind_param("iii", $incidentId, $eventId, $userId);
            $stmt->execute();
            
            // Update alert status to acknowledged
            $stmt = $conn->prepare("UPDATE alerts SET status = 'acknowledged', acknowledged_by = ?, acknowledged_at = NOW() 
                                   WHERE alert_id = ? AND status = 'new'");
            $stmt->bind_param("ii", $userId, $alertId);
            $stmt->execute();
        }
    }
    
    // Commit transaction
    $conn->commit();
    
    // Log the action
    logSecurityEvent('incident', 'info', "Created new incident: $title, ID: $incidentId", $userId, getClientIP());
    
    // Set success message
    $_SESSION['success_message'] = "Incident created successfully";
    
    // Redirect to the new incident details
    header("Location: incident-details.php?id=$incidentId");
    exit;
    
} catch (Exception $e) {
    // Roll back transaction on error
    $conn->rollback();
    
    // Log the error
    logError("Error creating incident: " . $e->getMessage());
    
    // Set error message
    $_SESSION['error_message'] = "Error creating incident: " . $e->getMessage();
    
    // Redirect back to incidents page
    header("Location: incidents.php");
    exit;
}

// Close the database connection
$conn->close();
