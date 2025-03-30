<?php
require_once 'config.php';

// Initialize secure session
initSecureSession();

// Check if user is authenticated, redirect to login if not
if (!isAuthenticated()) {
    header("Location: index.php");
    exit;
}

// Check if incident ID is provided
if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    header("Location: incidents.php");
    exit;
}

$incidentId = (int)$_GET['id'];
$userId = $_SESSION['user_id'];

// Connect to database
$conn = connectDB();

// Process form submissions
$message = '';
$messageType = '';

// Generate CSRF token for forms
$csrfToken = generateCSRFToken();

// Process status update
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_status') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        $message = "Invalid request";
        $messageType = "danger";
    } else {
        $newStatus = sanitizeInput($_POST['new_status']);
        $statusNote = sanitizeInput($_POST['status_note']);
        
        // Begin transaction
        $conn->begin_transaction();
        
        try {
            // Update incident status
            $stmt = $conn->prepare("UPDATE incidents SET status = ?, updated_at = NOW() WHERE incident_id = ?");
            $stmt->bind_param("si", $newStatus, $incidentId);
            $stmt->execute();
            
            // If status is 'closed', set closed_at timestamp
            if ($newStatus === 'closed') {
                $stmt = $conn->prepare("UPDATE incidents SET closed_at = NOW() WHERE incident_id = ?");
                $stmt->bind_param("i", $incidentId);
                $stmt->execute();
            }
            
            // Add status change to incident notes
            $noteContent = "Status changed to " . ucfirst(str_replace('_', ' ', $newStatus));
            if (!empty($statusNote)) {
                $noteContent .= ":\n" . $statusNote;
            }
            
            $stmt = $conn->prepare("INSERT INTO incident_notes (incident_id, user_id, content, created_at) VALUES (?, ?, ?, NOW())");
            $stmt->bind_param("iis", $incidentId, $userId, $noteContent);
            $stmt->execute();
            
            // Add action for status change
            $actionType = '';
            switch ($newStatus) {
                case 'assigned': $actionType = 'investigation'; break;
                case 'investigating': $actionType = 'investigation'; break;
                case 'contained': $actionType = 'containment'; break;
                case 'remediated': $actionType = 'remediation'; break;
                case 'closed': $actionType = 'recovery'; break;
                default: $actionType = 'other';
            }
            
            $actionDescription = "Status updated to " . ucfirst(str_replace('_', ' ', $newStatus));
            if (!empty($statusNote)) {
                $actionDescription .= ":\n" . $statusNote;
            }
            
            $stmt = $conn->prepare("INSERT INTO incident_actions (incident_id, action_type, description, performed_by, performed_at) 
                                  VALUES (?, ?, ?, ?, NOW())");
            $stmt->bind_param("issi", $incidentId, $actionType, $actionDescription, $userId);
            $stmt->execute();
            
            // Commit transaction
            $conn->commit();
            
            $message = "Incident status updated successfully";
            $messageType = "success";
            
            // Log the action
            logSecurityEvent('incident', 'info', "Updated incident ID: $incidentId status to $newStatus", $userId, getClientIP());
            
        } catch (Exception $e) {
            // Roll back transaction on error
            $conn->rollback();
            
            $message = "Error updating incident status: " . $e->getMessage();
            $messageType = "danger";
            
            // Log the error
            logError("Error updating incident status: " . $e->getMessage());
        }
    }
}

// Process add note
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add_note') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        $message = "Invalid request";
        $messageType = "danger";
    } else {
        $noteContent = sanitizeInput($_POST['note_content']);
        
        if (empty($noteContent)) {
            $message = "Note content cannot be empty";
            $messageType = "warning";
        } else {
            $stmt = $conn->prepare("INSERT INTO incident_notes (incident_id, user_id, content, created_at) VALUES (?, ?, ?, NOW())");
            $stmt->bind_param("iis", $incidentId, $userId, $noteContent);
            
            if ($stmt->execute()) {
                $message = "Note added successfully";
                $messageType = "success";
                
                // Log the action
                logSecurityEvent('incident', 'info', "Added note to incident ID: $incidentId", $userId, getClientIP());
            } else {
                $message = "Error adding note: " . $conn->error;
                $messageType = "danger";
            }
        }
    }
}

// Process add action
if ($_SERVER['METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add_action') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        $message = "Invalid request";
        $messageType = "danger";
    } else {
        $actionType = sanitizeInput($_POST['action_type']);
        $actionDescription = sanitizeInput($_POST['action_description']);
        
        if (empty($actionDescription)) {
            $message = "Action description cannot be empty";
            $messageType = "warning";
        } else {
            $stmt = $conn->prepare("INSERT INTO incident_actions (incident_id, action_type, description, performed_by, performed_at) 
                                  VALUES (?, ?, ?, ?, NOW())");
            $stmt->bind_param("issi", $incidentId, $actionType, $actionDescription, $userId);
            
            if ($stmt->execute()) {
                $message = "Action added successfully";
                $messageType = "success";
                
                // Log the action
                logSecurityEvent('incident', 'info', "Added action to incident ID: $incidentId", $userId, getClientIP());
            } else {
                $message = "Error adding action: " . $conn->error;
                $messageType = "danger";
            }
        }
    }
}

// Process assign incident
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'assign') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        $message = "Invalid request";
        $messageType = "danger";
    } else {
        $assignTo = intval($_POST['assign_to']);
        
        // Begin transaction
        $conn->begin_transaction();
        
        try {
            // Get analyst name for the note
            $analystName = "Unknown";
            $stmt = $conn->prepare("SELECT username FROM users WHERE user_id = ?");
            $stmt->bind_param("i", $assignTo);
            $stmt->execute();
            $result = $stmt->get_result();
            if ($row = $result->fetch_assoc()) {
                $analystName = $row['username'];
            }
            
            // Update incident
            $stmt = $conn->prepare("UPDATE incidents SET assigned_to = ?, status = 'assigned', updated_at = NOW() WHERE incident_id = ?");
            $stmt->bind_param("ii", $assignTo, $incidentId);
            $stmt->execute();
            
            // Add note for assignment
            $noteContent = "Incident assigned to $analystName";
            $stmt = $conn->prepare("INSERT INTO incident_notes (incident_id, user_id, content, created_at) VALUES (?, ?, ?, NOW())");
            $stmt->bind_param("iis", $incidentId, $userId, $noteContent);
            $stmt->execute();
            
            // Commit transaction
            $conn->commit();
            
            $message = "Incident assigned successfully";
            $messageType = "success";
            
            // Log the action
            logSecurityEvent('incident', 'info', "Assigned incident ID: $incidentId to user ID: $assignTo", $userId, getClientIP());
            
        } catch (Exception $e) {
            // Roll back transaction on error
            $conn->rollback();
            
            $message = "Error assigning incident: " . $e->getMessage();
            $messageType = "danger";
            
            // Log the error
            logError("Error assigning incident: " . $e->getMessage());
        }
    }
}

// Get incident details
$stmt = $conn->prepare("SELECT i.*, 
                        u1.username as created_by_name, 
                        u2.username as assigned_to_name 
                        FROM incidents i 
                        LEFT JOIN users u1 ON i.created_by = u1.user_id 
                        LEFT JOIN users u2 ON i.assigned_to = u2.user_id 
                        WHERE i.incident_id = ?");
$stmt->bind_param("i", $incidentId);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    header("Location: incidents.php");
    exit;
}

$incident = $result->fetch_assoc();

// Get incident notes
$notes = [];
$stmt = $conn->prepare("SELECT n.*, u.username, u.first_name, u.last_name 
                       FROM incident_notes n 
                       LEFT JOIN users u ON n.user_id = u.user_id 
                       WHERE n.incident_id = ? 
                       ORDER BY n.created_at DESC");
$stmt->bind_param("i", $incidentId);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $notes[] = $row;
}

// Get incident actions
$actions = [];
$stmt = $conn->prepare("SELECT a.*, u.username, u.first_name, u.last_name 
                       FROM incident_actions a 
                       LEFT JOIN users u ON a.performed_by = u.user_id 
                       WHERE a.incident_id = ? 
                       ORDER BY a.performed_at DESC");
$stmt->bind_param("i", $incidentId);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $actions[] = $row;
}

// Get linked events
$events = [];
$stmt = $conn->prepare("SELECT e.*, a.asset_name
                       FROM security_events e 
                       LEFT JOIN incident_events ie ON e.event_id = ie.event_id 
                       LEFT JOIN assets a ON e.asset_id = a.asset_id 
                       WHERE ie.incident_id = ? 
                       ORDER BY e.timestamp DESC");
$stmt->bind_param("i", $incidentId);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $events[] = $row;
}

// Get linked alerts
$alerts = [];
$stmt = $conn->prepare("SELECT a.* 
                       FROM alerts a 
                       JOIN incident_events ie ON a.event_id = ie.event_id 
                       WHERE ie.incident_id = ? 
                       ORDER BY a.created_at DESC");
$stmt->bind_param("i", $incidentId);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $alerts[] = $row;
}

// Get available analysts for assignment
$analysts = [];
$stmt = $conn->prepare("SELECT user_id, username, first_name, last_name 
                       FROM users 
                       WHERE role IN ('admin', 'manager', 'analyst') AND is_active = 1 
                       ORDER BY username");
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $analysts[$row['user_id']] = $row['username'] . ' (' . $row['first_name'] . ' ' . $row['last_name'] . ')';
}

// Close the database connection
$conn->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Incident #<?php echo $incidentId; ?> - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="assets/css/style.css">
    <!-- Include modern UI framework CSS (Bootstrap, etc.) -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Include Font Awesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-light">
    <!-- Include header/navigation -->
    <?php include 'includes/header.php'; ?>
    
    <div class="container-fluid">
        <div class="row">
            <!-- Include sidebar -->
            <?php include 'includes/sidebar.php'; ?>
            
            <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4 py-4">
                <nav aria-label="breadcrumb">
                    <ol class="breadcrumb">
                        <li class="breadcrumb-item"><a href="dashboard.php">Dashboard</a></li>
                        <li class="breadcrumb-item"><a href="incidents.php">Incidents</a></li>
                        <li class="breadcrumb-item active" aria-current="page">Incident #<?php echo $incidentId; ?></li>
                    </ol>
                </nav>

                <?php if (!empty($message)): ?>
                    <div class="alert alert-<?php echo $messageType; ?> alert-dismissible fade show" role="alert">
                        <?php echo $message; ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                <?php endif; ?>
                
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">
                        <i class="fas fa-file-alt"></i> Incident #<?php echo $incidentId; ?>
                        <span class="badge <?php 
                            switch ($incident['severity']) {
                                case 'critical': echo 'bg-danger'; break;
                                case 'high': echo 'bg-warning text-dark'; break;
                                case 'medium': echo 'bg-primary'; break;
                                case 'low': echo 'bg-success'; break;
                                default: echo 'bg-info';
                            }
                        ?>">
                            <?php echo ucfirst($incident['severity']); ?>
                        </span>
                        <span class="badge <?php 
                            switch ($incident['status']) {
                                case 'new': echo 'bg-danger'; break;
                                case 'assigned': echo 'bg-warning text-dark'; break;
                                case 'investigating': echo 'bg-info'; break;
                                case 'contained': echo 'bg-primary'; break;
                                case 'remediated': echo 'bg-success'; break;
                                case 'closed': echo 'bg-secondary'; break;
                                default: echo 'bg-info';
                            }
                        ?>">
                            <?php echo ucfirst($incident['status']); ?>
                        </span>
                    </h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <div class="btn-group me-2">
                            <button type="button" class="btn btn-sm btn-outline-secondary" onclick="window.print()">
                                <i class="fas fa-print"></i> Print
                            </button>
                            <button type="button" class="btn btn-sm btn-outline-secondary" data-bs-toggle="modal" data-bs-target="#exportModal">
                                <i class="fas fa-download"></i> Export
                            </button>
                        </div>
                        
                        <?php if ($incident['status'] !== 'closed'): ?>
                            <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#updateStatusModal">
                                <i class="fas fa-sync-alt"></i> Update Status
                            </button>
                        <?php endif; ?>
                    </div>
                </div>
                
                <div class="row mb-4">
                    <div class="col-md-8">
                        <!-- Incident Details Card -->
                        <div class="card mb-4">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0">Incident Details</h5>
                            </div>
                            <div class="card-body">
                                <h4><?php echo htmlspecialchars($incident['title']); ?></h4>
                                <div class="row mt-4">
                                    <div class="col-md-4">
                                        <p><strong>ID:</strong> <?php echo $incidentId; ?></p>
                                        <p><strong>Type:</strong> <?php echo ucfirst(str_replace('_', ' ', $incident['incident_type'])); ?></p>
                                        <p><strong>Severity:</strong> 
                                            <span class="badge <?php 
                                                switch ($incident['severity']) {
                                                    case 'critical': echo 'bg-danger'; break;
                                                    case 'high': echo 'bg-warning text-dark'; break;
                                                    case 'medium': echo 'bg-primary'; break;
                                                    case 'low': echo 'bg-success'; break;
                                                    default: echo 'bg-info';
                                                }
                                            ?>">
                                                <?php echo ucfirst($incident['severity']); ?>
                                            </span>
                                        </p>
                                    </div>
                                    <div class="col-md-4">
                                        <p><strong>Status:</strong> 
                                            <span class="badge <?php 
                                                switch ($incident['status']) {
                                                    case 'new': echo 'bg-danger'; break;
                                                    case 'assigned': echo 'bg-warning text-dark'; break;
                                                    case 'investigating': echo 'bg-info'; break;
                                                    case 'contained': echo 'bg-primary'; break;
                                                    case 'remediated': echo 'bg-success'; break;
                                                    case 'closed': echo 'bg-secondary'; break;
                                                    default: echo 'bg-info';
                                                }
                                            ?>">
                                                <?php echo ucfirst($incident['status']); ?>
                                            </span>
                                        </p>
                                        <p><strong>Created By:</strong> <?php echo htmlspecialchars($incident['created_by_name'] ?: 'Unknown'); ?></p>
                                        <p><strong>Created At:</strong> <?php echo date('Y-m-d H:i:s', strtotime($incident['created_at'])); ?></p>
                                    </div>
                                    <div class="col-md-4">
                                        <p><strong>Assigned To:</strong> 
                                            <?php if (!empty($incident['assigned_to_name'])): ?>
                                                <?php echo htmlspecialchars($incident['assigned_to_name']); ?>
                                            <?php else: ?>
                                                <span class="badge bg-light text-dark">Unassigned</span>
                                                <?php if (hasRole('admin', 'manager', 'analyst')): ?>
                                                    <button type="button" class="btn btn-sm btn-outline-primary ms-2" data-bs-toggle="modal" data-bs-target="#assignModal">
                                                        <i class="fas fa-user-plus"></i> Assign
                                                    </button>
                                                <?php endif; ?>
                                            <?php endif; ?>
                                        </p>
                                        <?php if ($incident['status'] === 'closed' && $incident['closed_at']): ?>
                                            <p><strong>Closed At:</strong> <?php echo date('Y-m-d H:i:s', strtotime($incident['closed_at'])); ?></p>
                                        <?php endif; ?>
                                    </div>
                                </div>
                                
                                <div class="mt-4">
                                    <h6>Description</h6>
                                    <div class="p-3 bg-light rounded">
                                        <?php echo nl2br(htmlspecialchars($incident['description'])); ?>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Incident Actions -->
                        <div class="card mb-4">
                            <div class="card-header bg-white d-flex justify-content-between align-items-center">
                                <h5 class="card-title mb-0">Actions Taken</h5>
                                <?php if (hasRole('admin', 'manager', 'analyst') && $incident['status'] !== 'closed'): ?>
                                    <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#addActionModal">
                                        <i class="fas fa-plus"></i> Add Action
                                    </button>
                                <?php endif; ?>
                            </div>
                            <div class="card-body">
                                <?php if (empty($actions)): ?>
                                    <p class="text-center text-muted py-3">No actions recorded yet</p>
                                <?php else: ?>
                                    <div class="timeline">
                                        <?php foreach ($actions as $action): ?>
                                            <div class="timeline-item">
                                                <div class="timeline-dot">
                                                    <?php 
                                                    $icon = 'tasks';
                                                    switch ($action['action_type']) {
                                                        case 'containment': $icon = 'shield-alt'; break;
                                                        case 'evidence_collection': $icon = 'search'; break;
                                                        case 'investigation': $icon = 'magnifying-glass'; break;
                                                        case 'remediation': $icon = 'wrench'; break;
                                                        case 'recovery': $icon = 'sync-alt'; break;
                                                    }
                                                    ?>
                                                    <i class="fas fa-<?php echo $icon; ?> fa-sm"></i>
                                                </div>
                                                <div class="timeline-date">
                                                    <?php echo date('M d, Y H:i', strtotime($action['performed_at'])); ?> by 
                                                    <strong><?php echo htmlspecialchars($action['username'] ?: 'Unknown'); ?></strong>
                                                </div>
                                                <div class="timeline-content">
                                                    <h6><?php echo ucfirst(str_replace('_', ' ', $action['action_type'])); ?></h6>
                                                    <p class="mb-0"><?php echo nl2br(htmlspecialchars($action['description'])); ?></p>
                                                </div>
                                            </div>
                                        <?php endforeach; ?>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                        
                        <!-- Linked Events and Alerts -->
                        <div class="card mb-4">
                            <div class="card-header bg-white">
                                <ul class="nav nav-tabs card-header-tabs" id="linkedEventsTab" role="tablist">
                                    <li class="nav-item" role="presentation">
                                        <button class="nav-link active" id="events-tab" data-bs-toggle="tab" data-bs-target="#events" type="button" role="tab" aria-controls="events" aria-selected="true">
                                            Events <span class="badge bg-secondary ms-1"><?php echo count($events); ?></span>
                                        </button>
                                    </li>
                                    <li class="nav-item" role="presentation">
                                        <button class="nav-link" id="alerts-tab" data-bs-toggle="tab" data-bs-target="#alerts" type="button" role="tab" aria-controls="alerts" aria-selected="false">
                                            Alerts <span class="badge bg-secondary ms-1"><?php echo count($alerts); ?></span>
                                        </button>
                                    </li>
                                </ul>
                            </div>
                            <div class="card-body">
                                <div class="tab-content" id="linkedEventsTabContent">
                                    <!-- Events Tab -->
                                    <div class="tab-pane fade show active" id="events" role="tabpanel" aria-labelledby="events-tab">
                                        <?php if (empty($events)): ?>
                                            <p class="text-center text-muted py-3">No events linked to this incident</p>
                                        <?php else: ?>
                                            <div class="table-responsive">
                                                <table class="table table-hover table-striped">
                                                    <thead>
                                                        <tr>
                                                            <th>Time</th>
                                                            <th>Type</th>
                                                            <th>Source</th>
                                                            <th>Description</th>
                                                            <th>Asset</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        <?php foreach ($events as $event): ?>
                                                            <tr>
                                                                <td><?php echo date('Y-m-d H:i:s', strtotime($event['timestamp'])); ?></td>
                                                                <td>
                                                                    <span class="badge bg-info">
                                                                        <?php echo ucfirst($event['event_type']); ?>
                                                                    </span>
                                                                </td>
                                                                <td><?php echo htmlspecialchars($event['source_ip'] ?: 'N/A'); ?></td>
                                                                <td><?php echo htmlspecialchars($event['description']); ?></td>
                                                                <td>
                                                                    <?php if (!empty($event['asset_name'])): ?>
                                                                        <a href="assets.php?asset_id=<?php echo $event['asset_id']; ?>">
                                                                            <?php echo htmlspecialchars($event['asset_name']); ?>
                                                                        </a>
                                                                    <?php else: ?>
                                                                        <span class="text-muted">N/A</span>
                                                                    <?php endif; ?>
                                                                </td>
                                                            </tr>
                                                        <?php endforeach; ?>
                                                    </tbody>
                                                </table>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                    
                                    <!-- Alerts Tab -->
                                    <div class="tab-pane fade" id="alerts" role="tabpanel" aria-labelledby="alerts-tab">
                                        <?php if (empty($alerts)): ?>
                                            <p class="text-center text-muted py-3">No alerts linked to this incident</p>
                                        <?php else: ?>
                                            <div class="table-responsive">
                                                <table class="table table-hover table-striped">
                                                    <thead>
                                                        <tr>
                                                            <th>Time</th>
                                                            <th>Severity</th>
                                                            <th>Alert</th>
                                                            <th>Status</th>
                                                            <th>Actions</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        <?php foreach ($alerts as $alert): ?>
                                                            <tr>
                                                                <td><?php echo date('Y-m-d H:i:s', strtotime($alert['created_at'])); ?></td>
                                                                <td>
                                                                    <span class="badge <?php 
                                                                        switch ($alert['severity']) {
                                                                            case 'critical': echo 'bg-danger'; break;
                                                                            case 'high': echo 'bg-warning text-dark'; break;
                                                                            case 'medium': echo 'bg-primary'; break;
                                                                            case 'low': echo 'bg-success'; break;
                                                                            default: echo 'bg-info';
                                                                        }
                                                                    ?>">
                                                                        <?php echo ucfirst($alert['severity']); ?>
                                                                    </span>
                                                                </td>
                                                                <td><?php echo htmlspecialchars($alert['alert_message']); ?></td>
                                                                <td>
                                                                    <span class="badge <?php 
                                                                        switch ($alert['status']) {
                                                                            case 'new': echo 'bg-danger'; break;
                                                                            case 'acknowledged': echo 'bg-warning text-dark'; break;
                                                                            case 'resolved': echo 'bg-success'; break;
                                                                            case 'false_positive': echo 'bg-secondary'; break;
                                                                            default: echo 'bg-info';
                                                                        }
                                                                    ?>">
                                                                        <?php echo ucfirst($alert['status']); ?>
                                                                    </span>
                                                                </td>
                                                                <td>
                                                                    <a href="alert-details.php?id=<?php echo $alert['alert_id']; ?>" class="btn btn-sm btn-outline-primary">
                                                                        <i class="fas fa-eye"></i> View
                                                                    </a>
                                                                </td>
                                                            </tr>
                                                        <?php endforeach; ?>
                                                    </tbody>
                                                </table>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-4">
                        <!-- Status Timeline Card -->
                        <div class="card mb-4">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0">Status Timeline</h5>
                            </div>
                            <div class="card-body p-0">
                                <div class="list-group list-group-flush">
                                    <div class="list-group-item d-flex justify-content-between align-items-center">
                                        <div>
                                            <i class="fas fa-plus-circle text-success me-2"></i> Created
                                            <div class="small text-muted"><?php echo date('M d, Y H:i', strtotime($incident['created_at'])); ?></div>
                                        </div>
                                        <span class="badge bg-success">Completed</span>
                                    </div>
                                    
                                    <div class="list-group-item d-flex justify-content-between align-items-center">
                                        <div>
                                            <i class="fas fa-user-plus text-<?php echo $incident['status'] === 'new' ? 'secondary' : 'success'; ?> me-2"></i> Assigned
                                            <?php if (!empty($incident['assigned_to_name'])): ?>
                                                <div class="small text-muted">To: <?php echo htmlspecialchars($incident['assigned_to_name']); ?></div>
                                            <?php endif; ?>
                                        </div>
                                        <span class="badge bg-<?php echo $incident['status'] === 'new' ? 'secondary' : 'success'; ?>">
                                            <?php echo $incident['status'] === 'new' ? 'Pending' : 'Completed'; ?>
                                        </span>
                                    </div>
                                    
                                    <div class="list-group-item d-flex justify-content-between align-items-center">
                                        <div>
                                            <i class="fas fa-search text-<?php echo in_array($incident['status'], ['new', 'assigned']) ? 'secondary' : 'success'; ?> me-2"></i> Investigation
                                        </div>
                                        <span class="badge bg-<?php 
                                            if ($incident['status'] === 'investigating') echo 'warning';
                                            else if (in_array($incident['status'], ['new', 'assigned'])) echo 'secondary';
                                            else echo 'success';
                                        ?>">
                                            <?php 
                                                if ($incident['status'] === 'investigating') echo 'In Progress';
                                                else if (in_array($incident['status'], ['new', 'assigned'])) echo 'Pending';
                                                else echo 'Completed';
                                            ?>
                                        </span>
                                    </div>
                                    
                                    <div class="list-group-item d-flex justify-content-between align-items-center">
                                        <div>
                                            <i class="fas fa-shield-alt text-<?php echo in_array($incident['status'], ['new', 'assigned', 'investigating']) ? 'secondary' : 'success'; ?> me-2"></i> Containment
                                        </div>
                                        <span class="badge bg-<?php 
                                            if ($incident['status'] === 'contained') echo 'primary';
                                            else if (in_array($incident['status'], ['new', 'assigned', 'investigating'])) echo 'secondary';
                                            else echo 'success';
                                        ?>">
                                            <?php 
                                                if ($incident['status'] === 'contained') echo 'In Progress';
                                                else if (in_array($incident['status'], ['new', 'assigned', 'investigating'])) echo 'Pending';
                                                else echo 'Completed';
                                            ?>
                                        </span>
                                    </div>
                                    
                                    <div class="list-group-item d-flex justify-content-between align-items-center">
                                        <div>
                                            <i class="fas fa-wrench text-<?php echo in_array($incident['status'], ['new', 'assigned', 'investigating', 'contained']) ? 'secondary' : 'success'; ?> me-2"></i> Remediation
                                        </div>
                                        <span class="badge bg-<?php 
                                            if ($incident['status'] === 'remediated') echo 'info';
                                            else if (in_array($incident['status'], ['new', 'assigned', 'investigating', 'contained'])) echo 'secondary';
                                            else echo 'success';
                                        ?>">
                                            <?php 
                                                if ($incident['status'] === 'remediated') echo 'In Progress';
                                                else if (in_array($incident['status'], ['new', 'assigned', 'investigating', 'contained'])) echo 'Pending';
                                                else echo 'Completed';
                                            ?>
                                        </span>
                                    </div>
                                    
                                    <div class="list-group-item d-flex justify-content-between align-items-center">
                                        <div>
                                            <i class="fas fa-check-circle text-<?php echo $incident['status'] === 'closed' ? 'success' : 'secondary'; ?> me-2"></i> Closed
                                            <?php if ($incident['status'] === 'closed' && $incident['closed_at']): ?>
                                                <div class="small text-muted"><?php echo date('M d, Y H:i', strtotime($incident['closed_at'])); ?></div>
                                            <?php endif; ?>
                                        </div>
                                        <span class="badge bg-<?php echo $incident['status'] === 'closed' ? 'success' : 'secondary'; ?>">
                                            <?php echo $incident['status'] === 'closed' ? 'Completed' : 'Pending'; ?>
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Notes Card -->
                        <div class="card mb-4">
                            <div class="card-header bg-white d-flex justify-content-between align-items-center">
                                <h5 class="card-title mb-0">Notes</h5>
                                <?php if (hasRole('admin', 'manager', 'analyst') && $incident['status'] !== 'closed'): ?>
                                    <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#addNoteModal">
                                        <i class="fas fa-plus"></i> Add Note
                                    </button>
                                <?php endif; ?>
                            </div>
                            <div class="card-body">
                                <?php if (empty($notes)): ?>
                                    <p class="text-center text-muted py-3">No notes recorded yet</p>
                                <?php else: ?>
                                    <?php foreach ($notes as $note): ?>
                                        <div class="mb-3 pb-3 border-bottom">
                                            <div class="d-flex justify-content-between align-items-center mb-2">
                                                <div>
                                                    <strong><?php echo htmlspecialchars($note['username'] ?: 'Unknown'); ?></strong>
                                                    <span class="text-muted ms-2 small"><?php echo date('M d, Y H:i', strtotime($note['created_at'])); ?></span>
                                                </div>
                                            </div>
                                            <div>
                                                <?php echo nl2br(htmlspecialchars($note['content'])); ?>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>
    
    <!-- Update Status Modal -->
    <div class="modal fade" id="updateStatusModal" tabindex="-1" aria-labelledby="updateStatusModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" name="action" value="update_status">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="updateStatusModalLabel">Update Incident Status</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="new_status" class="form-label">New Status</label>
                            <select class="form-select" id="new_status" name="new_status" required>
                                <option value="">-- Select Status --</option>
                                
                                <?php if (in_array($incident['status'], ['new', 'assigned'])): ?>
                                    <option value="investigating">Investigating</option>
                                <?php endif; ?>
                                
                                <?php if (in_array($incident['status'], ['investigating'])): ?>
                                    <option value="contained">Contained</option>
                                <?php endif; ?>
                                
                                <?php if (in_array($incident['status'], ['contained'])): ?>
                                    <option value="remediated">Remediated</option>
                                <?php endif; ?>
                                
                                <?php if (in_array($incident['status'], ['remediated'])): ?>
                                    <option value="closed">Closed</option>
                                <?php endif; ?>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <label for="status_note" class="form-label">Status Change Note</label>
                            <textarea class="form-control" id="status_note" name="status_note" rows="3" placeholder="Enter details about this status change"></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Update Status</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Add Note Modal -->
    <div class="modal fade" id="addNoteModal" tabindex="-1" aria-labelledby="addNoteModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" name="action" value="add_note">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="addNoteModalLabel">Add Note</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="note_content" class="form-label">Note</label>
                            <textarea class="form-control" id="note_content" name="note_content" rows="5" required></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Note</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Add Action Modal -->
    <div class="modal fade" id="addActionModal" tabindex="-1" aria-labelledby="addActionModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" name="action" value="add_action">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="addActionModalLabel">Add Action</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="action_type" class="form-label">Action Type</label>
                            <select class="form-select" id="action_type" name="action_type" required>
                                <option value="">-- Select Action Type --</option>
                                <option value="containment">Containment</option>
                                <option value="evidence_collection">Evidence Collection</option>
                                <option value="investigation">Investigation</option>
                                <option value="remediation">Remediation</option>
                                <option value="recovery">Recovery</option>
                                <option value="other">Other</option>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <label for="action_description" class="form-label">Description</label>
                            <textarea class="form-control" id="action_description" name="action_description" rows="5" required></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Action</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Assign Incident Modal -->
    <div class="modal fade" id="assignModal" tabindex="-1" aria-labelledby="assignModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" name="action" value="assign">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="assignModalLabel">Assign Incident</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="assign_to" class="form-label">Assign To</label>
                            <select class="form-select" id="assign_to" name="assign_to" required>
                                <option value="">-- Select Analyst --</option>
                                <?php foreach ($analysts as $id => $name): ?>
                                    <option value="<?php echo $id; ?>"><?php echo htmlspecialchars($name); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Assign</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Export Modal -->
    <div class="modal fade" id="exportModal" tabindex="-1" aria-labelledby="exportModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <form action="export-incident.php" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" name="incident_id" value="<?php echo $incidentId; ?>">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="exportModalLabel">Export Incident</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="export_format" class="form-label">Format</label>
                            <select class="form-select" id="export_format" name="export_format">
                                <option value="pdf">PDF Report</option>
                                <option value="json">JSON</option>
                                <option value="csv">CSV</option>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="include_notes" name="include_notes" value="1" checked>
                                <label class="form-check-label" for="include_notes">
                                    Include notes
                                </label>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="include_actions" name="include_actions" value="1" checked>
                                <label class="form-check-label" for="include_actions">
                                    Include actions
                                </label>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="include_events" name="include_events" value="1" checked>
                                <label class="form-check-label" for="include_events">
                                    Include events and alerts
                                </label>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Export</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Include footer -->
    <?php include 'includes/footer.php'; ?>
    
    <!-- Include JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>