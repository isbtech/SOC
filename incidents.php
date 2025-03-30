<?php
require_once 'config.php';

// Initialize secure session
initSecureSession();

// Check if user is authenticated, redirect to login if not
if (!isAuthenticated()) {
    header("Location: index.php");
    exit;
}

// Connect to database
$conn = connectDB();

// Process bulk actions
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && isset($_POST['selected_incidents'])) {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        $message = "Invalid request";
        $messageType = "danger";
    } else {
        $selectedIncidents = $_POST['selected_incidents'];
        $action = $_POST['action'];
        $userId = $_SESSION['user_id'];
        
        // Make sure selected incidents is an array
        if (!is_array($selectedIncidents)) {
            $selectedIncidents = [$selectedIncidents];
        }
        
        // Convert to integers to prevent SQL injection
        $selectedIncidents = array_map('intval', $selectedIncidents);
        $selectedIncidentsStr = implode(',', $selectedIncidents);
        
        if (!empty($selectedIncidentsStr)) {
            switch ($action) {
                case 'assign':
                    if (isset($_POST['assign_to']) && !empty($_POST['assign_to'])) {
                        $assignTo = intval($_POST['assign_to']);
                        $query = "UPDATE incidents SET status = 'assigned', assigned_to = ?, updated_at = NOW() 
                                 WHERE incident_id IN ($selectedIncidentsStr) AND status = 'new'";
                        $stmt = $conn->prepare($query);
                        $stmt->bind_param("i", $assignTo);
                        $stmt->execute();
                        
                        $message = $stmt->affected_rows . " incident(s) assigned successfully";
                        $messageType = "success";
                        
                        // Log the action
                        logSecurityEvent('security', 'info', "Bulk assigned incidents: $selectedIncidentsStr to user ID: $assignTo", $userId, getClientIP());
                    } else {
                        $message = "No analyst selected for assignment";
                        $messageType = "warning";
                    }
                    break;
                    
                case 'investigating':
                    $query = "UPDATE incidents SET status = 'investigating', updated_at = NOW() 
                             WHERE incident_id IN ($selectedIncidentsStr) AND (status = 'new' OR status = 'assigned')";
                    $stmt = $conn->prepare($query);
                    $stmt->execute();
                    
                    $message = $stmt->affected_rows . " incident(s) marked as investigating";
                    $messageType = "success";
                    
                    // Log the action
                    logSecurityEvent('security', 'info', "Bulk marked incidents as investigating: $selectedIncidentsStr", $userId, getClientIP());
                    break;
                    
                case 'contained':
                    $query = "UPDATE incidents SET status = 'contained', updated_at = NOW() 
                             WHERE incident_id IN ($selectedIncidentsStr) AND status = 'investigating'";
                    $stmt = $conn->prepare($query);
                    $stmt->execute();
                    
                    $message = $stmt->affected_rows . " incident(s) marked as contained";
                    $messageType = "success";
                    
                    // Log the action
                    logSecurityEvent('security', 'info', "Bulk marked incidents as contained: $selectedIncidentsStr", $userId, getClientIP());
                    break;
                    
                case 'remediated':
                    $query = "UPDATE incidents SET status = 'remediated', updated_at = NOW() 
                             WHERE incident_id IN ($selectedIncidentsStr) AND status = 'contained'";
                    $stmt = $conn->prepare($query);
                    $stmt->execute();
                    
                    $message = $stmt->affected_rows . " incident(s) marked as remediated";
                    $messageType = "success";
                    
                    // Log the action
                    logSecurityEvent('security', 'info', "Bulk marked incidents as remediated: $selectedIncidentsStr", $userId, getClientIP());
                    break;
                    
                case 'close':
                    $query = "UPDATE incidents SET status = 'closed', closed_at = NOW(), updated_at = NOW() 
                             WHERE incident_id IN ($selectedIncidentsStr) AND status = 'remediated'";
                    $stmt = $conn->prepare($query);
                    $stmt->execute();
                    
                    $message = $stmt->affected_rows . " incident(s) closed successfully";
                    $messageType = "success";
                    
                    // Log the action
                    logSecurityEvent('security', 'info', "Bulk closed incidents: $selectedIncidentsStr", $userId, getClientIP());
                    break;
                    
                default:
                    $message = "Invalid action";
                    $messageType = "danger";
            }
        } else {
            $message = "No incidents selected";
            $messageType = "warning";
        }
    }
}

// Pagination parameters
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$limit = isset($_GET['limit']) ? intval($_GET['limit']) : 25;
$offset = ($page - 1) * $limit;

// Filtering parameters
$filterSeverity = isset($_GET['severity']) ? $_GET['severity'] : '';
$filterStatus = isset($_GET['status']) ? $_GET['status'] : '';
$filterType = isset($_GET['incident_type']) ? $_GET['incident_type'] : '';
$filterAssignedTo = isset($_GET['assigned_to']) ? intval($_GET['assigned_to']) : 0;
$filterDateFrom = isset($_GET['date_from']) ? $_GET['date_from'] : '';
$filterDateTo = isset($_GET['date_to']) ? $_GET['date_to'] : '';
$searchQuery = isset($_GET['search']) ? $_GET['search'] : '';

// Build the query
$query = "SELECT i.incident_id, i.title, i.description, i.incident_type, i.severity, i.status, 
         i.created_at, i.updated_at, i.closed_at, i.assigned_to,
         u1.username as created_by_name, u2.username as assigned_to_name 
         FROM incidents i 
         LEFT JOIN users u1 ON i.created_by = u1.user_id 
         LEFT JOIN users u2 ON i.assigned_to = u2.user_id 
         WHERE 1=1";

$countQuery = "SELECT COUNT(*) as total FROM incidents i 
              LEFT JOIN users u1 ON i.created_by = u1.user_id 
              LEFT JOIN users u2 ON i.assigned_to = u2.user_id 
              WHERE 1=1";

$params = [];
$types = "";

// Add filters to the query
if (!empty($filterSeverity)) {
    $query .= " AND i.severity = ?";
    $countQuery .= " AND i.severity = ?";
    $params[] = $filterSeverity;
    $types .= "s";
}

if (!empty($filterStatus)) {
    $query .= " AND i.status = ?";
    $countQuery .= " AND i.status = ?";
    $params[] = $filterStatus;
    $types .= "s";
}

if (!empty($filterType)) {
    $query .= " AND i.incident_type = ?";
    $countQuery .= " AND i.incident_type = ?";
    $params[] = $filterType;
    $types .= "s";
}

if (!empty($filterAssignedTo)) {
    $query .= " AND i.assigned_to = ?";
    $countQuery .= " AND i.assigned_to = ?";
    $params[] = $filterAssignedTo;
    $types .= "i";
}

if (!empty($filterDateFrom)) {
    $query .= " AND i.created_at >= ?";
    $countQuery .= " AND i.created_at >= ?";
    $params[] = $filterDateFrom . " 00:00:00";
    $types .= "s";
}

if (!empty($filterDateTo)) {
    $query .= " AND i.created_at <= ?";
    $countQuery .= " AND i.created_at <= ?";
    $params[] = $filterDateTo . " 23:59:59";
    $types .= "s";
}

if (!empty($searchQuery)) {
    $query .= " AND (i.title LIKE ? OR i.description LIKE ? OR u1.username LIKE ? OR u2.username LIKE ?)";
    $countQuery .= " AND (i.title LIKE ? OR i.description LIKE ? OR u1.username LIKE ? OR u2.username LIKE ?)";
    $searchParam = "%" . $searchQuery . "%";
    $params[] = $searchParam;
    $params[] = $searchParam;
    $params[] = $searchParam;
    $params[] = $searchParam;
    $types .= "ssss";
}

// Add sorting and pagination
$query .= " ORDER BY i.created_at DESC LIMIT ? OFFSET ?";
$params[] = $limit;
$params[] = $offset;
$types .= "ii";

// Get total count for pagination
$countStmt = $conn->prepare($countQuery);
if (!empty($types)) {
    $typeString = substr($types, 0, -2); // Remove 'ii' for limit and offset
    if (!empty($typeString)) {
        $countStmt->bind_param($typeString, ...array_slice($params, 0, -2));
    }
}
$countStmt->execute();
$countResult = $countStmt->get_result();
$totalRows = $countResult->fetch_assoc()['total'];
$totalPages = ceil($totalRows / $limit);

// Get incidents
$stmt = $conn->prepare($query);
if (!empty($types)) {
    $stmt->bind_param($types, ...$params);
}
$stmt->execute();
$result = $stmt->get_result();
$incidents = [];
while ($row = $result->fetch_assoc()) {
    $incidents[] = $row;
}

// Get severity counts for filter
$severityCounts = [];
$query = "SELECT severity, COUNT(*) as count FROM incidents GROUP BY severity ORDER BY 
         FIELD(severity, 'critical', 'high', 'medium', 'low')";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $severityCounts[$row['severity']] = $row['count'];
}

// Get status counts for filter
$statusCounts = [];
$query = "SELECT status, COUNT(*) as count FROM incidents GROUP BY status ORDER BY 
         FIELD(status, 'new', 'assigned', 'investigating', 'contained', 'remediated', 'closed')";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $statusCounts[$row['status']] = $row['count'];
}

// Get incident types for filter
$incidentTypes = [];
$query = "SELECT incident_type, COUNT(*) as count FROM incidents GROUP BY incident_type ORDER BY incident_type";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $incidentTypes[$row['incident_type']] = $row['count'];
}

// Get analysts for assignment
$analysts = [];
$query = "SELECT user_id, username, first_name, last_name FROM users WHERE role IN ('admin', 'manager', 'analyst') AND is_active = 1 ORDER BY username";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $analysts[$row['user_id']] = $row['username'] . ' (' . $row['first_name'] . ' ' . $row['last_name'] . ')';
}

// Close the database connection
$conn->close();

// Generate CSRF token for forms
$csrfToken = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Incidents - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="assets/css/style.css">
    <!-- Include modern UI framework CSS (Bootstrap, etc.) -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Include Font Awesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- Include Flatpickr for date pickers -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
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
                        <li class="breadcrumb-item active" aria-current="page">Incidents</li>
                    </ol>
                </nav>

                <?php if (isset($message)): ?>
                    <div class="alert alert-<?php echo $messageType; ?> alert-dismissible fade show" role="alert">
                        <?php echo $message; ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                <?php endif; ?>
                
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2"><i class="fas fa-file-alt"></i> Incidents</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <div class="btn-group me-2">
                            <button type="button" class="btn btn-sm btn-outline-secondary" id="refreshBtn">
                                <i class="fas fa-sync-alt"></i> Refresh
                            </button>
                            <button type="button" class="btn btn-sm btn-outline-secondary" data-bs-toggle="modal" data-bs-target="#exportModal">
                                <i class="fas fa-download"></i> Export
                            </button>
                        </div>
                        <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#createIncidentModal">
                            <i class="fas fa-plus"></i> New Incident
                        </button>
                    </div>
                </div>
                
                <!-- Filter panel -->
                <div class="card mb-3">
                    <div class="card-header bg-white">
                        <div class="d-flex justify-content-between align-items-center">
                            <h5 class="card-title mb-0">Filters</h5>
                            <button class="btn btn-link" type="button" data-bs-toggle="collapse" data-bs-target="#filterCollapse" aria-expanded="true" aria-controls="filterCollapse">
                                <i class="fas fa-chevron-down"></i>
                            </button>
                        </div>
                    </div>
                    <div class="collapse show" id="filterCollapse">
                        <div class="card-body">
                            <form action="incidents.php" method="get" id="filterForm">
                                <div class="row g-3">
                                    <div class="col-md-3">
                                        <label for="severity" class="form-label">Severity</label>
                                        <select class="form-select" id="severity" name="severity">
                                            <option value="">All Severities</option>
                                            <option value="critical" <?php echo $filterSeverity === 'critical' ? 'selected' : ''; ?>>
                                                Critical (<?php echo isset($severityCounts['critical']) ? $severityCounts['critical'] : 0; ?>)
                                            </option>
                                            <option value="high" <?php echo $filterSeverity === 'high' ? 'selected' : ''; ?>>
                                                High (<?php echo isset($severityCounts['high']) ? $severityCounts['high'] : 0; ?>)
                                            </option>
                                            <option value="medium" <?php echo $filterSeverity === 'medium' ? 'selected' : ''; ?>>
                                                Medium (<?php echo isset($severityCounts['medium']) ? $severityCounts['medium'] : 0; ?>)
                                            </option>
                                            <option value="low" <?php echo $filterSeverity === 'low' ? 'selected' : ''; ?>>
                                                Low (<?php echo isset($severityCounts['low']) ? $severityCounts['low'] : 0; ?>)
                                            </option>
                                        </select>
                                    </div>
                                    <div class="col-md-3">
                                        <label for="status" class="form-label">Status</label>
                                        <select class="form-select" id="status" name="status">
                                            <option value="">All Statuses</option>
                                            <option value="new" <?php echo $filterStatus === 'new' ? 'selected' : ''; ?>>
                                                New (<?php echo isset($statusCounts['new']) ? $statusCounts['new'] : 0; ?>)
                                            </option>
                                            <option value="assigned" <?php echo $filterStatus === 'assigned' ? 'selected' : ''; ?>>
                                                Assigned (<?php echo isset($statusCounts['assigned']) ? $statusCounts['assigned'] : 0; ?>)
                                            </option>
                                            <option value="investigating" <?php echo $filterStatus === 'investigating' ? 'selected' : ''; ?>>
                                                Investigating (<?php echo isset($statusCounts['investigating']) ? $statusCounts['investigating'] : 0; ?>)
                                            </option>
                                            <option value="contained" <?php echo $filterStatus === 'contained' ? 'selected' : ''; ?>>
                                                Contained (<?php echo isset($statusCounts['contained']) ? $statusCounts['contained'] : 0; ?>)
                                            </option>
                                            <option value="remediated" <?php echo $filterStatus === 'remediated' ? 'selected' : ''; ?>>
                                                Remediated (<?php echo isset($statusCounts['remediated']) ? $statusCounts['remediated'] : 0; ?>)
                                            </option>
                                            <option value="closed" <?php echo $filterStatus === 'closed' ? 'selected' : ''; ?>>
                                                Closed (<?php echo isset($statusCounts['closed']) ? $statusCounts['closed'] : 0; ?>)
                                            </option>
                                        </select>
                                    </div>
                                    <div class="col-md-3">
                                        <label for="incident_type" class="form-label">Incident Type</label>
                                        <select class="form-select" id="incident_type" name="incident_type">
                                            <option value="">All Types</option>
                                            <?php foreach ($incidentTypes as $type => $count): ?>
                                                <option value="<?php echo $type; ?>" <?php echo $filterType === $type ? 'selected' : ''; ?>>
                                                    <?php echo ucfirst(str_replace('_', ' ', $type)); ?> (<?php echo $count; ?>)
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                    <div class="col-md-3">
                                        <label for="assigned_to" class="form-label">Assigned To</label>
                                        <select class="form-select" id="assigned_to" name="assigned_to">
                                            <option value="0">All Analysts</option>
                                            <?php foreach ($analysts as $id => $name): ?>
                                                <option value="<?php echo $id; ?>" <?php echo $filterAssignedTo === $id ? 'selected' : ''; ?>>
                                                    <?php echo htmlspecialchars($name); ?>
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                    <div class="col-md-3">
                                        <label for="date_from" class="form-label">Date From</label>
                                        <input type="text" class="form-control datepicker" id="date_from" name="date_from" placeholder="YYYY-MM-DD" value="<?php echo htmlspecialchars($filterDateFrom); ?>">
                                    </div>
                                    <div class="col-md-3">
                                        <label for="date_to" class="form-label">Date To</label>
                                        <input type="text" class="form-control datepicker" id="date_to" name="date_to" placeholder="YYYY-MM-DD" value="<?php echo htmlspecialchars($filterDateTo); ?>">
                                    </div>
                                    <div class="col-md-4">
                                        <label for="search" class="form-label">Search</label>
                                        <input type="text" class="form-control" id="search" name="search" placeholder="Search incidents..." value="<?php echo htmlspecialchars($searchQuery); ?>">
                                    </div>
                                    <div class="col-md-2">
                                        <label for="limit" class="form-label">Show</label>
                                        <select class="form-select" id="limit" name="limit">
                                            <option value="25" <?php echo $limit === 25 ? 'selected' : ''; ?>>25 per page</option>
                                            <option value="50" <?php echo $limit === 50 ? 'selected' : ''; ?>>50 per page</option>
                                            <option value="100" <?php echo $limit === 100 ? 'selected' : ''; ?>>100 per page</option>
                                        </select>
                                    </div>
                                    <div class="col-12">
                                        <button type="submit" class="btn btn-primary">
                                            <i class="fas fa-filter"></i> Apply Filters
                                        </button>
                                        <a href="incidents.php" class="btn btn-outline-secondary">
                                            <i class="fas fa-undo"></i> Clear Filters
                                        </a>
                                    </div>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
                
                <!-- Incident Status Progress Bar -->
                <div class="card mb-3">
                    <div class="card-body py-2">
                        <div class="progress-container">
                            <ul class="progress-tracker progress-tracker--text progress-tracker--center">
                                <li class="progress-step <?php echo isset($statusCounts['new']) && $statusCounts['new'] > 0 ? 'is-active' : ''; ?> <?php echo isset($statusCounts['new']) && $statusCounts['new'] > 0 ? 'has-count' : ''; ?>">
                                    <div class="progress-marker"><?php echo isset($statusCounts['new']) ? $statusCounts['new'] : '0'; ?></div>
                                    <div class="progress-text">
                                        <h4 class="progress-title">New</h4>
                                    </div>
                                </li>
                                <li class="progress-step <?php echo isset($statusCounts['assigned']) && $statusCounts['assigned'] > 0 ? 'is-active' : ''; ?> <?php echo isset($statusCounts['assigned']) && $statusCounts['assigned'] > 0 ? 'has-count' : ''; ?>">
                                    <div class="progress-marker"><?php echo isset($statusCounts['assigned']) ? $statusCounts['assigned'] : '0'; ?></div>
                                    <div class="progress-text">
                                        <h4 class="progress-title">Assigned</h4>
                                    </div>
                                </li>
                                <li class="progress-step <?php echo isset($statusCounts['investigating']) && $statusCounts['investigating'] > 0 ? 'is-active' : ''; ?> <?php echo isset($statusCounts['investigating']) && $statusCounts['investigating'] > 0 ? 'has-count' : ''; ?>">
                                    <div class="progress-marker"><?php echo isset($statusCounts['investigating']) ? $statusCounts['investigating'] : '0'; ?></div>
                                    <div class="progress-text">
                                        <h4 class="progress-title">Investigating</h4>
                                    </div>
                                </li>
                                <li class="progress-step <?php echo isset($statusCounts['contained']) && $statusCounts['contained'] > 0 ? 'is-active' : ''; ?> <?php echo isset($statusCounts['contained']) && $statusCounts['contained'] > 0 ? 'has-count' : ''; ?>">
                                    <div class="progress-marker"><?php echo isset($statusCounts['contained']) ? $statusCounts['contained'] : '0'; ?></div>
                                    <div class="progress-text">
                                        <h4 class="progress-title">Contained</h4>
                                    </div>
                                </li>
                                <li class="progress-step <?php echo isset($statusCounts['remediated']) && $statusCounts['remediated'] > 0 ? 'is-active' : ''; ?> <?php echo isset($statusCounts['remediated']) && $statusCounts['remediated'] > 0 ? 'has-count' : ''; ?>">
                                    <div class="progress-marker"><?php echo isset($statusCounts['remediated']) ? $statusCounts['remediated'] : '0'; ?></div>
                                    <div class="progress-text">
                                        <h4 class="progress-title">Remediated</h4>
                                    </div>
                                </li>
                                <li class="progress-step <?php echo isset($statusCounts['closed']) && $statusCounts['closed'] > 0 ? 'is-active' : ''; ?> <?php echo isset($statusCounts['closed']) && $statusCounts['closed'] > 0 ? 'has-count' : ''; ?>">
                                    <div class="progress-marker"><?php echo isset($statusCounts['closed']) ? $statusCounts['closed'] : '0'; ?></div>
                                    <div class="progress-text">
                                        <h4 class="progress-title">Closed</h4>
                                    </div>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
                
                <!-- Incidents table -->
                <div class="card">
                    <div class="card-body p-0">
                        <form id="bulkActionForm" method="post">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                            <input type="hidden" name="action" id="bulkActionType" value="">
                            
                            <!-- Bulk action toolbar -->
                            <div class="border-bottom p-3">
                                <div class="d-flex flex-wrap align-items-center">
                                    <div class="form-check me-3">
                                        <input class="form-check-input" type="checkbox" id="selectAll">
                                        <label class="form-check-label" for="selectAll">Select All</label>
                                    </div>
                                    
                                    <div class="dropdown me-3">
                                        <button class="btn btn-outline-secondary dropdown-toggle" type="button" id="bulkActionDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                                            Bulk Actions
                                        </button>
                                        <ul class="dropdown-menu" aria-labelledby="bulkActionDropdown">
                                            <li><a class="dropdown-item" href="#" onclick="showAssignModal(); return false;">Assign to Analyst</a></li>
                                            <li><a class="dropdown-item bulk-action" href="#" data-action="investigating">Mark as Investigating</a></li>
                                            <li><a class="dropdown-item bulk-action" href="#" data-action="contained">Mark as Contained</a></li>
                                            <li><a class="dropdown-item bulk-action" href="#" data-action="remediated">Mark as Remediated</a></li>
                                            <li><a class="dropdown-item bulk-action" href="#" data-action="close">Close Incidents</a></li>
                                        </ul>
                                    </div>
                                    
                                    <div class="ms-auto">
                                        <span class="text-muted">
                                            <?php echo $totalRows; ?> incident(s) found
                                        </span>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="table-responsive">
                                <table class="table table-hover align-middle mb-0">
                                    <thead class="table-light">
                                        <tr>
                                            <th style="width: 40px;"></th>
                                            <th style="width: 100px;">ID</th>
                                            <th style="width: 170px;">Created</th>
                                            <th style="width: 100px;">Severity</th>
                                            <th>Title</th>
                                            <th style="width: 130px;">Type</th>
                                            <th style="width: 130px;">Status</th>
                                            <th style="width: 150px;">Assigned To</th>
                                            <th style="width: 100px;">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php if (empty($incidents)): ?>
                                            <tr>
                                                <td colspan="9" class="text-center py-4">No incidents found matching your criteria</td>
                                            </tr>
                                        <?php else: ?>
                                            <?php foreach ($incidents as $incident): ?>
                                                <tr>
                                                    <td>
                                                        <div class="form-check">
                                                            <input class="form-check-input incident-checkbox" type="checkbox" name="selected_incidents[]" value="<?php echo $incident['incident_id']; ?>">
                                                        </div>
                                                    </td>
                                                    <td>
                                                        <span class="badge bg-secondary">#<?php echo $incident['incident_id']; ?></span>
                                                    </td>
                                                    <td>
                                                        <div><?php echo date('Y-m-d', strtotime($incident['created_at'])); ?></div>
                                                        <small class="text-muted"><?php echo date('H:i:s', strtotime($incident['created_at'])); ?></small>
                                                    </td>
                                                    <td>
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
                                                    </td>
                                                    <td>
                                                        <a href="incident-details.php?id=<?php echo $incident['incident_id']; ?>" class="text-decoration-none">
                                                            <?php echo htmlspecialchars(substr($incident['title'], 0, 100)) . (strlen($incident['title']) > 100 ? '...' : ''); ?>
                                                        </a>
                                                        <?php if (!empty($incident['created_by_name'])): ?>
                                                            <div class="small text-muted">Created by: <?php echo htmlspecialchars($incident['created_by_name']); ?></div>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td>
                                                        <?php echo ucfirst(str_replace('_', ' ', $incident['incident_type'])); ?>
                                                    </td>
                                                    <td>
                                                        <span class="badge <?php 
                                                            switch ($incident['status']) {
                                                                case 'new': echo 'bg-danger'; break;
                                                                case 'assigned': echo 'bg-warning text-dark'; break;
                                                                case 'investigating': echo 'bg-info'; break;
                                                                case 'contained': echo 'bg-primary'; break;
                                                                case 'remediated': echo 'bg-success'; break;
                                                                case 'closed': echo 'bg-secondary'; break;
                                                                default: echo 'bg-light text-dark';
                                                            }
                                                        ?>">
                                                            <?php echo ucfirst($incident['status']); ?>
                                                        </span>
                                                        <?php if ($incident['status'] === 'closed' && !empty($incident['closed_at'])): ?>
                                                            <div class="small text-muted">
                                                                <?php echo date('Y-m-d', strtotime($incident['closed_at'])); ?>
                                                            </div>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td>
                                                        <?php if (!empty($incident['assigned_to_name'])): ?>
                                                            <span class="badge bg-secondary"><?php echo htmlspecialchars($incident['assigned_to_name']); ?></span>
                                                        <?php else: ?>
                                                            <span class="badge bg-light text-dark">Unassigned</span>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td>
                                                        <div class="dropdown">
                                                            <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" id="actionDropdown<?php echo $incident['incident_id']; ?>" data-bs-toggle="dropdown" aria-expanded="false">
                                                                <i class="fas fa-ellipsis-v"></i>
                                                            </button>
                                                            <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="actionDropdown<?php echo $incident['incident_id']; ?>">
                                                                <li><a class="dropdown-item" href="incident-details.php?id=<?php echo $incident['incident_id']; ?>"><i class="fas fa-eye"></i> View Details</a></li>
                                                                
                                                                <?php if ($incident['status'] === 'new'): ?>
                                                                    <li><a class="dropdown-item" href="#" onclick="showSingleAssignModal(<?php echo $incident['incident_id']; ?>); return false;"><i class="fas fa-user-plus"></i> Assign</a></li>
                                                                <?php endif; ?>
                                                                
                                                                <?php if ($incident['status'] === 'new' || $incident['status'] === 'assigned'): ?>
                                                                    <li><a class="dropdown-item single-action" href="#" data-id="<?php echo $incident['incident_id']; ?>" data-action="investigating"><i class="fas fa-search"></i> Mark Investigating</a></li>
                                                                <?php endif; ?>
                                                                
                                                                <?php if ($incident['status'] === 'investigating'): ?>
                                                                    <li><a class="dropdown-item single-action" href="#" data-id="<?php echo $incident['incident_id']; ?>" data-action="contained"><i class="fas fa-shield-alt"></i> Mark Contained</a></li>
                                                                <?php endif; ?>
                                                                
                                                                <?php if ($incident['status'] === 'contained'): ?>
                                                                    <li><a class="dropdown-item single-action" href="#" data-id="<?php echo $incident['incident_id']; ?>" data-action="remediated"><i class="fas fa-check-circle"></i> Mark Remediated</a></li>
                                                                <?php endif; ?>
                                                                
                                                                <?php if ($incident['status'] === 'remediated'): ?>
                                                                    <li><a class="dropdown-item single-action" href="#" data-id="<?php echo $incident['incident_id']; ?>" data-action="close"><i class="fas fa-check-double"></i> Close Incident</a></li>
                                                                <?php endif; ?>
                                                                
                                                                <li><hr class="dropdown-divider"></li>
                                                                <li><a class="dropdown-item" href="#" onclick="window.open('print-incident.php?id=<?php echo $incident['incident_id']; ?>', '_blank'); return false;"><i class="fas fa-print"></i> Print Report</a></li>
                                                            </ul>
                                                        </div>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        <?php endif; ?>
                                    </tbody>
                                </table>
                            </div>
                        </form>
                        
                        <!-- Pagination -->
                        <?php if ($totalPages > 1): ?>
                            <div class="d-flex justify-content-between align-items-center p-3">
                                <div>
                                    Showing <?php echo $offset + 1; ?> to <?php echo min($offset + $limit, $totalRows); ?> of <?php echo $totalRows; ?> incidents
                                </div>
                                <nav aria-label="Page navigation">
                                    <ul class="pagination mb-0">
                                        <li class="page-item <?php echo $page <= 1 ? 'disabled' : ''; ?>">
                                            <a class="page-link" href="<?php echo '?' . http_build_query(array_merge($_GET, ['page' => $page - 1])); ?>" aria-label="Previous">
                                                <span aria-hidden="true">&laquo;</span>
                                            </a>
                                        </li>
                                        <?php
                                        $startPage = max(1, $page - 2);
                                        $endPage = min($totalPages, $page + 2);
                                        
                                        if ($startPage > 1) {
                                            echo '<li class="page-item"><a class="page-link" href="?' . http_build_query(array_merge($_GET, ['page' => 1])) . '">1</a></li>';
                                            if ($startPage > 2) {
                                                echo '<li class="page-item disabled"><span class="page-link">...</span></li>';
                                            }
                                        }
                                        
                                        for ($i = $startPage; $i <= $endPage; $i++) {
                                            echo '<li class="page-item ' . ($page == $i ? 'active' : '') . '"><a class="page-link" href="?' . http_build_query(array_merge($_GET, ['page' => $i])) . '">' . $i . '</a></li>';
                                        }
                                        
                                        if ($endPage < $totalPages) {
                                            if ($endPage < $totalPages - 1) {
                                                echo '<li class="page-item disabled"><span class="page-link">...</span></li>';
                                            }
                                            echo '<li class="page-item"><a class="page-link" href="?' . http_build_query(array_merge($_GET, ['page' => $totalPages])) . '">' . $totalPages . '</a></li>';
                                        }
                                        ?>
                                        <li class="page-item <?php echo $page >= $totalPages ? 'disabled' : ''; ?>">
                                            <a class="page-link" href="<?php echo '?' . http_build_query(array_merge($_GET, ['page' => $page + 1])); ?>" aria-label="Next">
                                                <span aria-hidden="true">&raquo;</span>
                                            </a>
                                        </li>
                                    </ul>
                                </nav>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </main>
        </div>
    </div>
    
    <!-- Create New Incident Modal -->
    <div class="modal fade" id="createIncidentModal" tabindex="-1" aria-labelledby="createIncidentModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <form action="create-incident.php" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="createIncidentModalLabel">Create New Incident</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="incident_title" class="form-label">Incident Title</label>
                            <input type="text" class="form-control" id="incident_title" name="incident_title" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="incident_description" class="form-label">Incident Description</label>
                            <textarea class="form-control" id="incident_description" name="incident_description" rows="4" required></textarea>
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
                                        <option value="critical">Critical</option>
                                        <option value="high">High</option>
                                        <option value="medium">Medium</option>
                                        <option value="low">Low</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="assign_to" class="form-label">Assign To (Optional)</label>
                            <select class="form-select" id="assign_to" name="assign_to">
                                <option value="">-- Unassigned --</option>
                                <?php foreach ($analysts as $id => $name): ?>
                                    <option value="<?php echo $id; ?>"><?php echo htmlspecialchars($name); ?></option>
                                <?php endforeach; ?>
                            </select>
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
    
    <!-- Assign to Analyst Modal (Bulk) -->
    <div class="modal fade" id="assignModal" tabindex="-1" aria-labelledby="assignModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="assignModalLabel">Assign Incidents to Analyst</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label for="bulk_assign_to" class="form-label">Select Analyst</label>
                        <select class="form-select" id="bulk_assign_to" name="assign_to">
                            <option value="">-- Select Analyst --</option>
                            <?php foreach ($analysts as $id => $name): ?>
                                <option value="<?php echo $id; ?>"><?php echo htmlspecialchars($name); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" id="confirmBulkAssign">Assign</button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Assign to Analyst Modal (Single) -->
    <div class="modal fade" id="singleAssignModal" tabindex="-1" aria-labelledby="singleAssignModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="singleAssignModalLabel">Assign Incident to Analyst</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" id="single_incident_id" value="">
                    <div class="mb-3">
                        <label for="single_assign_to" class="form-label">Select Analyst</label>
                        <select class="form-select" id="single_assign_to" name="assign_to">
                            <option value="">-- Select Analyst --</option>
                            <?php foreach ($analysts as $id => $name): ?>
                                <option value="<?php echo $id; ?>"><?php echo htmlspecialchars($name); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" id="confirmSingleAssign">Assign</button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Export Modal -->
    <div class="modal fade" id="exportModal" tabindex="-1" aria-labelledby="exportModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <form action="export-incidents.php" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="exportModalLabel">Export Incidents</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="export_format" class="form-label">Format</label>
                            <select class="form-select" id="export_format" name="export_format">
                                <option value="csv">CSV</option>
                                <option value="json">JSON</option>
                                <option value="pdf">PDF</option>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <label for="export_scope" class="form-label">Scope</label>
                            <select class="form-select" id="export_scope" name="export_scope">
                                <option value="filtered">Current filtered results (<?php echo $totalRows; ?> incidents)</option>
                                <option value="selected">Selected incidents only</option>
                                <option value="all">All incidents</option>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="include_notes" name="include_notes" value="1">
                                <label class="form-check-label" for="include_notes">
                                    Include incident notes
                                </label>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="include_actions" name="include_actions" value="1">
                                <label class="form-check-label" for="include_actions">
                                    Include incident actions
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
    
    <!-- Single Action Form (Hidden) -->
    <form id="singleActionForm" method="post" style="display: none;">
        <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
        <input type="hidden" name="action" id="singleActionType" value="">
        <input type="hidden" name="selected_incidents[]" id="singleActionId" value="">
    </form>
    
    <!-- Include footer -->
    <?php include 'includes/footer.php'; ?>
    
    <!-- Include JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Initialize date pickers
            flatpickr('.datepicker', {
                dateFormat: 'Y-m-d',
                allowInput: true
            });
            
            // Select all checkbox functionality
            document.getElementById('selectAll').addEventListener('change', function() {
                const isChecked = this.checked;
                document.querySelectorAll('.incident-checkbox').forEach(function(checkbox) {
                    checkbox.checked = isChecked;
                });
            });
            
            // Bulk actions
            document.querySelectorAll('.bulk-action').forEach(function(button) {
                button.addEventListener('click', function(e) {
                    e.preventDefault();
                    
                    // Check if any incidents are selected
                    const checkedBoxes = document.querySelectorAll('.incident-checkbox:checked');
                    if (checkedBoxes.length === 0) {
                        alert('Please select at least one incident.');
                        return;
                    }
                    
                    // Set the action type
                    const action = this.getAttribute('data-action');
                    document.getElementById('bulkActionType').value = action;
                    
                    // Confirm before submission
                    let actionText = '';
                    switch (action) {
                        case 'investigating':
                            actionText = 'mark as investigating';
                            break;
                        case 'contained':
                            actionText = 'mark as contained';
                            break;
                        case 'remediated':
                            actionText = 'mark as remediated';
                            break;
                        case 'close':
                            actionText = 'close';
                            break;
                    }
                    
                    if (confirm(`Are you sure you want to ${actionText} ${checkedBoxes.length} incident(s)?`)) {
                        document.getElementById('bulkActionForm').submit();
                    }
                });
            });
            
            // Single actions
            document.querySelectorAll('.single-action').forEach(function(button) {
                button.addEventListener('click', function(e) {
                    e.preventDefault();
                    
                    const incidentId = this.getAttribute('data-id');
                    const action = this.getAttribute('data-action');
                    
                    document.getElementById('singleActionType').value = action;
                    document.getElementById('singleActionId').value = incidentId;
                    
                    // Confirm before submission
                    let actionText = '';
                    switch (action) {
                        case 'investigating':
                            actionText = 'mark as investigating';
                            break;
                        case 'contained':
                            actionText = 'mark as contained';
                            break;
                        case 'remediated':
                            actionText = 'mark as remediated';
                            break;
                        case 'close':
                            actionText = 'close';
                            break;
                    }
                    
                    if (confirm(`Are you sure you want to ${actionText} this incident?`)) {
                        document.getElementById('singleActionForm').submit();
                    }
                });
            });
            
            // Refresh button
            document.getElementById('refreshBtn').addEventListener('click', function() {
                window.location.reload();
            });
            
            // Assign modal (bulk)
            document.getElementById('confirmBulkAssign').addEventListener('click', function() {
                const assignTo = document.getElementById('bulk_assign_to').value;
                
                if (!assignTo) {
                    alert('Please select an analyst.');
                    return;
                }
                
                // Check if any incidents are selected
                const checkedBoxes = document.querySelectorAll('.incident-checkbox:checked');
                if (checkedBoxes.length === 0) {
                    alert('Please select at least one incident.');
                    return;
                }
                
                document.getElementById('bulkActionType').value = 'assign';
                
                // Append the assign_to field to the form
                const assignToInput = document.createElement('input');
                assignToInput.type = 'hidden';
                assignToInput.name = 'assign_to';
                assignToInput.value = assignTo;
                document.getElementById('bulkActionForm').appendChild(assignToInput);
                
                // Submit the form
                document.getElementById('bulkActionForm').submit();
            });
            
            // Assign modal (single)
            document.getElementById('confirmSingleAssign').addEventListener('click', function() {
                const assignTo = document.getElementById('single_assign_to').value;
                const incidentId = document.getElementById('single_incident_id').value;
                
                if (!assignTo) {
                    alert('Please select an analyst.');
                    return;
                }
                
                document.getElementById('singleActionType').value = 'assign';
                document.getElementById('singleActionId').value = incidentId;
                
                // Append the assign_to field to the form
                const assignToInput = document.createElement('input');
                assignToInput.type = 'hidden';
                assignToInput.name = 'assign_to';
                assignToInput.value = assignTo;
                document.getElementById('singleActionForm').appendChild(assignToInput);
                
                // Submit the form
                document.getElementById('singleActionForm').submit();
            });
        });
        
        // Show bulk assign modal
        function showAssignModal() {
            // Check if any incidents are selected
            const checkedBoxes = document.querySelectorAll('.incident-checkbox:checked');
            if (checkedBoxes.length === 0) {
                alert('Please select at least one incident.');
                return;
            }
            
            // Show the modal
            const assignModal = new bootstrap.Modal(document.getElementById('assignModal'));
            assignModal.show();
        }
        
        // Show single assign modal
        function showSingleAssignModal(incidentId) {
            document.getElementById('single_incident_id').value = incidentId;
            
            // Show the modal
            const singleAssignModal = new bootstrap.Modal(document.getElementById('singleAssignModal'));
            singleAssignModal.show();
        }
    </script>
    
    <!-- Custom CSS for Progress Tracker -->
    <style>
        .progress-tracker {
            display: flex;
            margin: 0;
            padding: 0;
            list-style: none;
        }
        
        .progress-step {
            flex: 1;
            position: relative;
            text-align: center;
            padding: 0;
        }
        
        .progress-tracker::before {
            content: '';
            position: absolute;
            top: 25px;
            left: 0;
            width: 100%;
            height: 2px;
            background-color: #dee2e6;
            z-index: 0;
        }
        
        .progress-step:first-child::before {
            content: none;
        }
        
        .progress-marker {
            display: flex;
            justify-content: center;
            align-items: center;
            position: relative;
            width: 50px;
            height: 50px;
            padding-bottom: 2px;
            margin: 0 auto 10px auto;
            z-index: 1;
            background-color: #f8f9fa;
            border: 2px solid #dee2e6;
            border-radius: 50%;
            color: #6c757d;
            font-weight: 600;
        }
        
        .progress-step.is-active .progress-marker {
            background-color: #0d6efd;
            border-color: #0d6efd;
            color: white;
        }
        
        .progress-step.has-count .progress-marker {
            background-color: #0d6efd;
            border-color: #0d6efd;
            color: white;
        }
        
        .progress-text {
            display: block;
            padding: 0 10px;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .progress-title {
            font-size: 0.9rem;
            margin-top: 0;
            margin-bottom: 0;
            font-weight: 600;
        }
    </style>
</body>
</html>