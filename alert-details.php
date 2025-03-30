<?php
require_once 'config.php';

// Initialize secure session
initSecureSession();

// Check if user is authenticated, redirect to login if not
if (!isAuthenticated()) {
    header("Location: index.php");
    exit;
}

// Check if alert ID is provided
if (!isset($stmt->close();

// Close the database connection
$conn->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Alert Details - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="assets/css/style.css">
    <!-- Include modern UI framework CSS (Bootstrap, etc.) -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Include Font Awesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- Include Code highlighting for logs -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/styles/default.min.css">
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
                        <li class="breadcrumb-item"><a href="alerts.php">Alerts</a></li>
                        <li class="breadcrumb-item active" aria-current="page">Alert #<?php echo $alertId; ?></li>
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
                        <i class="fas fa-bell"></i> Alert Details 
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
                    </h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <?php if ($alert['status'] === 'new'): ?>
                            <form method="post" class="me-2">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                                <input type="hidden" name="action" value="acknowledge">
                                <button type="submit" class="btn btn-warning">
                                    <i class="fas fa-check-circle"></i> Acknowledge
                                </button>
                            </form>
                        <?php endif; ?>
                        
                        <?php if ($alert['status'] !== 'resolved' && $alert['status'] !== 'false_positive'): ?>
                            <button type="button" class="btn btn-success me-2" data-bs-toggle="modal" data-bs-target="#resolveModal">
                                <i class="fas fa-check-double"></i> Resolve
                            </button>
                        <?php endif; ?>
                        
                        <?php if (count($incidents) === 0): ?>
                            <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#createIncidentModal">
                                <i class="fas fa-file-alt"></i> Create Incident
                            </button>
                        <?php endif; ?>
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-md-8">
                        <!-- Alert Information -->
                        <div class="card mb-4">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0">Alert Information</h5>
                            </div>
                            <div class="card-body">
                                <h4><?php echo htmlspecialchars($alert['alert_message']); ?></h4>
                                <div class="row mt-4">
                                    <div class="col-md-6">
                                        <p><strong>Alert ID:</strong> <?php echo $alertId; ?></p>
                                        <p><strong>Rule:</strong> <?php echo htmlspecialchars($alert['rule_name'] ?? 'N/A'); ?></p>
                                        <p><strong>Severity:</strong> 
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
                                        </p>
                                        <p><strong>Status:</strong> 
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
                                        </p>
                                    </div>
                                    <div class="col-md-6">
                                        <p><strong>Created:</strong> <?php echo date('Y-m-d H:i:s', strtotime($alert['created_at'])); ?></p>
                                        <p><strong>Event Time:</strong> <?php echo date('Y-m-d H:i:s', strtotime($alert['event_timestamp'] ?? $alert['created_at'])); ?></p>
                                        <p><strong>Asset:</strong> <?php echo htmlspecialchars($alert['asset_name'] ?? 'N/A'); ?></p>
                                        <p><strong>Event Type:</strong> <?php echo ucfirst($alert['event_type'] ?? 'N/A'); ?></p>
                                    </div>
                                </div>
                                
                                <?php if ($alert['status'] === 'acknowledged' || $alert['status'] === 'resolved'): ?>
                                    <div class="row mt-3">
                                        <div class="col-md-6">
                                            <?php if ($alert['status'] === 'acknowledged'): ?>
                                                <p><strong>Acknowledged By:</strong> <?php echo htmlspecialchars($alert['acknowledged_by_name'] ?? 'N/A'); ?></p>
                                                <p><strong>Acknowledged At:</strong> <?php echo $alert['acknowledged_at'] ? date('Y-m-d H:i:s', strtotime($alert['acknowledged_at'])) : 'N/A'; ?></p>
                                            <?php endif; ?>
                                        </div>
                                        <div class="col-md-6">
                                            <?php if ($alert['status'] === 'resolved'): ?>
                                                <p><strong>Resolved By:</strong> <?php echo htmlspecialchars($alert['resolved_by_name'] ?? 'N/A'); ?></p>
                                                <p><strong>Resolved At:</strong> <?php echo $alert['resolved_at'] ? date('Y-m-d H:i:s', strtotime($alert['resolved_at'])) : 'N/A'; ?></p>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                <?php endif; ?>
                                
                                <?php if (!empty($alert['rule_description'])): ?>
                                <div class="mt-4">
                                    <h6>Rule Description</h6>
                                    <p><?php echo htmlspecialchars($alert['rule_description']); ?></p>
                                </div>
                                <?php endif; ?>
                            </div>
                        </div>
                        
                        <!-- Event Details -->
                        <div class="card mb-4">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0">Event Details</h5>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <p><strong>Source IP:</strong> <?php echo htmlspecialchars($alert['source_ip'] ?? 'N/A'); ?></p>
                                        <p><strong>Destination IP:</strong> <?php echo htmlspecialchars($alert['destination_ip'] ?? 'N/A'); ?></p>
                                    </div>
                                    <div class="col-md-6">
                                        <p><strong>Event Type:</strong> <?php echo ucfirst($alert['event_type'] ?? 'N/A'); ?></p>
                                        <p><strong>Event Time:</strong> <?php echo date('Y-m-d H:i:s', strtotime($alert['event_timestamp'] ?? $alert['created_at'])); ?></p>
                                    </div>
                                </div>
                                
                                <?php if (!empty($alert['event_description'])): ?>
                                <div class="mt-3">
                                    <h6>Description</h6>
                                    <p><?php echo htmlspecialchars($alert['event_description']); ?></p>
                                </div>
                                <?php endif; ?>
                                
                                <?php if (!empty($alert['raw_log'])): ?>
                                <div class="mt-4">
                                    <h6>Raw Log</h6>
                                    <div class="bg-dark p-3 rounded">
                                        <pre><code class="language-json"><?php echo htmlspecialchars($alert['raw_log']); ?></code></pre>
                                    </div>
                                </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-4">
                        <!-- Linked Incidents -->
                        <div class="card mb-4">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0">Linked Incidents</h5>
                            </div>
                            <div class="card-body">
                                <?php if (empty($incidents)): ?>
                                    <p class="text-center text-muted py-3">No incidents linked to this alert</p>
                                    <div class="d-grid">
                                        <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#createIncidentModal">
                                            <i class="fas fa-file-alt"></i> Create Incident
                                        </button>
                                    </div>
                                <?php else: ?>
                                    <div class="list-group">
                                        <?php foreach ($incidents as $incident): ?>
                                            <a href="incident-details.php?id=<?php echo $incident['incident_id']; ?>" class="list-group-item list-group-item-action">
                                                <div class="d-flex w-100 justify-content-between">
                                                    <h6 class="mb-1"><?php echo htmlspecialchars($incident['title']); ?></h6>
                                                    <span class="badge <?php 
                                                        switch ($incident['severity']) {
                                                            case 'critical': echo 'bg-danger'; break;
                                                            case 'high': echo 'bg-warning text-dark'; break;
                                                            case 'medium': echo 'bg-primary'; break;
                                                            default: echo 'bg-success';
                                                        }
                                                    ?>"><?php echo ucfirst($incident['severity']); ?></span>
                                                </div>
                                                <small class="text-muted">Status: <?php echo ucfirst($incident['status']); ?></small>
                                            </a>
                                        <?php endforeach; ?>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                        
                        <!-- Similar Alerts -->
                        <div class="card mb-4">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0">Similar Alerts</h5>
                            </div>
                            <div class="card-body">
                                <p class="text-center text-muted py-3">
                                    <i class="fas fa-search"></i> Looking for similar alerts...
                                </p>
                                <div class="d-grid">
                                    <a href="alerts.php?source_ip=<?php echo urlencode($alert['source_ip'] ?? ''); ?>" class="btn btn-outline-secondary">
                                        <i class="fas fa-filter"></i> Find Alerts from Same Source
                                    </a>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Threat Intelligence -->
                        <div class="card mb-4">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0">Threat Intelligence</h5>
                            </div>
                            <div class="card-body">
                                <p class="text-center text-muted py-3">
                                    <i class="fas fa-globe"></i> No threat intelligence data available
                                </p>
                                <div class="d-grid">
                                    <button type="button" class="btn btn-outline-primary">
                                        <i class="fas fa-search"></i> Lookup in Threat Database
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>
    
    <!-- Resolve Alert Modal -->
    <div class="modal fade" id="resolveModal" tabindex="-1" aria-labelledby="resolveModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" name="action" value="resolve">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="resolveModalLabel">Resolve Alert</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="resolution_notes" class="form-label">Resolution Notes</label>
                            <textarea class="form-control" id="resolution_notes" name="resolution_notes" rows="4" required></textarea>
                            <div class="form-text">Describe how this alert was resolved or why it's being marked as resolved.</div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-success">Resolve Alert</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Create Incident Modal -->
    <div class="modal fade" id="createIncidentModal" tabindex="-1" aria-labelledby="createIncidentModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" name="action" value="create_incident">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="createIncidentModalLabel">Create Incident from Alert</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="incident_title" class="form-label">Incident Title</label>
                            <input type="text" class="form-control" id="incident_title" name="incident_title" value="Incident from Alert #<?php echo $alertId; ?>: <?php echo htmlspecialchars(substr($alert['alert_message'], 0, 50)) . (strlen($alert['alert_message']) > 50 ? '...' : ''); ?>" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="incident_description" class="form-label">Incident Description</label>
                            <textarea class="form-control" id="incident_description" name="incident_description" rows="4" required><?php echo "This incident was automatically created from Alert #$alertId.\n\nAlert Message: " . htmlspecialchars($alert['alert_message']) . "\n\nSeverity: " . ucfirst($alert['severity']) . "\nSource IP: " . ($alert['source_ip'] ?? 'N/A') . "\nDestination IP: " . ($alert['destination_ip'] ?? 'N/A'); ?></textarea>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="incident_type" class="form-label">Incident Type</label>
                                    <select class="form-select" id="incident_type" name="incident_type" required>
                                        <option value="">-- Select Type --</option>
                                        <option value="malware">Malware</option>
                                        <option value="phishing">Phishing</option>
                                        <option value="unauthorized_access">Unauthorized Access</option>
                                        <option value="data_breach">Data Breach</option>
                                        <option value="denial_of_service">Denial of Service</option>
                                        <option value="insider_threat">Insider Threat</option>
                                        <option value="other">Other</option>
                                    </select>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="incident_severity" class="form-label">Severity</label>
                                    <select class="form-select" id="incident_severity" name="incident_severity" required>
                                        <option value="">-- Select Severity --</option>
                                        <option value="critical" <?php echo $alert['severity'] === 'critical' ? 'selected' : ''; ?>>Critical</option>
                                        <option value="high" <?php echo $alert['severity'] === 'high' ? 'selected' : ''; ?>>High</option>
                                        <option value="medium" <?php echo $alert['severity'] === 'medium' ? 'selected' : ''; ?>>Medium</option>
                                        <option value="low" <?php echo $alert['severity'] === 'low' ? 'selected' : ''; ?>>Low</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Create Incident</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Include footer -->
    <?php include 'includes/footer.php'; ?>
    
    <!-- Include JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/highlight.min.js"></script>
    <script>
        // Initialize code highlighting
        document.addEventListener('DOMContentLoaded', (event) => {
            document.querySelectorAll('pre code').forEach((el) => {
                hljs.highlightElement(el);
            });
        });
    </script>
</body>
</html>_GET['id']) || !is_numeric($_GET['id'])) {
    header("Location: alerts.php");
    exit;
}

$alertId = (int)$_GET['id'];
$userId = $_SESSION['user_id'];

// Connect to database
$conn = connectDB();

// Process form submissions
$message = '';
$messageType = '';

// Generate CSRF token for forms
$csrfToken = generateCSRFToken();

// Handle alert acknowledgment
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'acknowledge') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        $message = "Invalid request";
        $messageType = "danger";
    } else {
        $stmt = $conn->prepare("UPDATE alerts SET status = 'acknowledged', acknowledged_by = ?, acknowledged_at = NOW() WHERE alert_id = ? AND status = 'new'");
        $stmt->bind_param("ii", $userId, $alertId);
        $stmt->execute();
        
        if ($stmt->affected_rows > 0) {
            $message = "Alert successfully acknowledged";
            $messageType = "success";
            
            // Log the action
            logSecurityEvent('security', 'info', "Alert ID $alertId acknowledged", $userId, getClientIP());
        } else {
            $message = "Alert could not be acknowledged or is already acknowledged";
            $messageType = "warning";
        }
        $stmt->close();
    }
}

// Handle alert resolution
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'resolve') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        $message = "Invalid request";
        $messageType = "danger";
    } else {
        // Get resolution notes
        $resolutionNotes = sanitizeInput($_POST['resolution_notes']);
        
        $stmt = $conn->prepare("UPDATE alerts SET status = 'resolved', resolved_by = ?, resolved_at = NOW() WHERE alert_id = ? AND (status = 'new' OR status = 'acknowledged')");
        $stmt->bind_param("ii", $userId, $alertId);
        $stmt->execute();
        
        if ($stmt->affected_rows > 0) {
            $message = "Alert successfully resolved";
            $messageType = "success";
            
            // Log resolution notes
            $stmt = $conn->prepare("INSERT INTO incident_notes (incident_id, user_id, content) SELECT incident_id, ?, ? FROM incident_events WHERE event_id = (SELECT event_id FROM alerts WHERE alert_id = ?)");
            $stmt->bind_param("isi", $userId, $resolutionNotes, $alertId);
            $stmt->execute();
            
            // Log the action
            logSecurityEvent('security', 'info', "Alert ID $alertId resolved", $userId, getClientIP());
        } else {
            $message = "Alert could not be resolved or is already resolved";
            $messageType = "warning";
        }
        $stmt->close();
    }
}

// Handle create incident from alert
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'create_incident') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        $message = "Invalid request";
        $messageType = "danger";
    } else {
        // Get incident details
        $incidentTitle = sanitizeInput($_POST['incident_title']);
        $incidentDesc = sanitizeInput($_POST['incident_description']);
        $incidentType = sanitizeInput($_POST['incident_type']);
        $incidentSeverity = sanitizeInput($_POST['incident_severity']);
        
        // Begin transaction
        $conn->begin_transaction();
        
        try {
            // Create new incident
            $stmt = $conn->prepare("INSERT INTO incidents (title, description, incident_type, severity, status, created_by) VALUES (?, ?, ?, ?, 'new', ?)");
            $stmt->bind_param("ssssi", $incidentTitle, $incidentDesc, $incidentType, $incidentSeverity, $userId);
            $stmt->execute();
            
            $incidentId = $conn->insert_id;
            
            // Link the event to the incident
            $stmt = $conn->prepare("INSERT INTO incident_events (incident_id, event_id, added_by) SELECT ?, event_id, ? FROM alerts WHERE alert_id = ?");
            $stmt->bind_param("iii", $incidentId, $userId, $alertId);
            $stmt->execute();
            
            // Update alert status
            $stmt = $conn->prepare("UPDATE alerts SET status = 'acknowledged', acknowledged_by = ?, acknowledged_at = NOW() WHERE alert_id = ? AND status = 'new'");
            $stmt->bind_param("ii", $userId, $alertId);
            $stmt->execute();
            
            // Commit transaction
            $conn->commit();
            
            $message = "Incident created successfully";
            $messageType = "success";
            
            // Log the action
            logSecurityEvent('security', 'info', "Incident created from Alert ID $alertId", $userId, getClientIP());
            
        } catch (Exception $e) {
            // Roll back transaction on error
            $conn->rollback();
            $message = "Error creating incident: " . $e->getMessage();
            $messageType = "danger";
        }
    }
}

// Get alert details
$stmt = $conn->prepare("SELECT a.*, r.rule_name, r.description as rule_description, e.source_ip, e.destination_ip, e.raw_log, 
                      e.event_type, e.description as event_description, e.timestamp as event_timestamp, 
                      ack.username as acknowledged_by_name, res.username as resolved_by_name, 
                      asset.asset_name 
                      FROM alerts a 
                      LEFT JOIN alert_rules r ON a.rule_id = r.rule_id 
                      LEFT JOIN security_events e ON a.event_id = e.event_id 
                      LEFT JOIN users ack ON a.acknowledged_by = ack.user_id 
                      LEFT JOIN users res ON a.resolved_by = res.user_id 
                      LEFT JOIN assets asset ON e.asset_id = asset.asset_id 
                      WHERE a.alert_id = ?");
$stmt->bind_param("i", $alertId);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    header("Location: alerts.php");
    exit;
}

$alert = $result->fetch_assoc();
$stmt->close();

// Check if this alert is linked to any incidents
$incidents = [];
$stmt = $conn->prepare("SELECT i.incident_id, i.title, i.status, i.severity 
                      FROM incidents i 
                      JOIN incident_events ie ON i.incident_id = ie.incident_id 
                      WHERE ie.event_id = ?");
$stmt->bind_param("i", $alert['event_id']);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $incidents[] = $row;
}
$