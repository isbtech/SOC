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
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && isset($_POST['selected_alerts'])) {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        $message = "Invalid request";
        $messageType = "danger";
    } else {
        $selectedAlerts = $_POST['selected_alerts'];
        $action = $_POST['action'];
        $userId = $_SESSION['user_id'];
        
        // Make sure selected alerts is an array
        if (!is_array($selectedAlerts)) {
            $selectedAlerts = [$selectedAlerts];
        }
        
        // Convert to integers to prevent SQL injection
        $selectedAlerts = array_map('intval', $selectedAlerts);
        $selectedAlertsStr = implode(',', $selectedAlerts);
        
        if (!empty($selectedAlertsStr)) {
            switch ($action) {
                case 'acknowledge':
                    $query = "UPDATE alerts SET status = 'acknowledged', acknowledged_by = ?, acknowledged_at = NOW() 
                             WHERE alert_id IN ($selectedAlertsStr) AND status = 'new'";
                    $stmt = $conn->prepare($query);
                    $stmt->bind_param("i", $userId);
                    $stmt->execute();
                    
                    $message = $stmt->affected_rows . " alert(s) acknowledged successfully";
                    $messageType = "success";
                    
                    // Log the action
                    logSecurityEvent('security', 'info', "Bulk acknowledged alerts: $selectedAlertsStr", $userId, getClientIP());
                    break;
                    
                case 'resolve':
                    $query = "UPDATE alerts SET status = 'resolved', resolved_by = ?, resolved_at = NOW() 
                             WHERE alert_id IN ($selectedAlertsStr) AND (status = 'new' OR status = 'acknowledged')";
                    $stmt = $conn->prepare($query);
                    $stmt->bind_param("i", $userId);
                    $stmt->execute();
                    
                    $message = $stmt->affected_rows . " alert(s) resolved successfully";
                    $messageType = "success";
                    
                    // Log the action
                    logSecurityEvent('security', 'info', "Bulk resolved alerts: $selectedAlertsStr", $userId, getClientIP());
                    break;
                    
                case 'false_positive':
                    $query = "UPDATE alerts SET status = 'false_positive', resolved_by = ?, resolved_at = NOW() 
                             WHERE alert_id IN ($selectedAlertsStr) AND (status = 'new' OR status = 'acknowledged')";
                    $stmt = $conn->prepare($query);
                    $stmt->bind_param("i", $userId);
                    $stmt->execute();
                    
                    $message = $stmt->affected_rows . " alert(s) marked as false positive";
                    $messageType = "success";
                    
                    // Log the action
                    logSecurityEvent('security', 'info', "Bulk marked alerts as false positive: $selectedAlertsStr", $userId, getClientIP());
                    break;
                    
                default:
                    $message = "Invalid action";
                    $messageType = "danger";
            }
        } else {
            $message = "No alerts selected";
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
$filterSourceIP = isset($_GET['source_ip']) ? $_GET['source_ip'] : '';
$filterRuleId = isset($_GET['rule_id']) ? intval($_GET['rule_id']) : 0;
$filterDateFrom = isset($_GET['date_from']) ? $_GET['date_from'] : '';
$filterDateTo = isset($_GET['date_to']) ? $_GET['date_to'] : '';
$searchQuery = isset($_GET['search']) ? $_GET['search'] : '';

// Build the query
$query = "SELECT a.alert_id, a.alert_message, a.severity, a.status, a.created_at, r.rule_name, 
         e.source_ip, e.destination_ip, u.username as acknowledged_by 
         FROM alerts a 
         LEFT JOIN alert_rules r ON a.rule_id = r.rule_id 
         LEFT JOIN security_events e ON a.event_id = e.event_id 
         LEFT JOIN users u ON a.acknowledged_by = u.user_id 
         WHERE 1=1";

$countQuery = "SELECT COUNT(*) as total FROM alerts a 
              LEFT JOIN alert_rules r ON a.rule_id = r.rule_id 
              LEFT JOIN security_events e ON a.event_id = e.event_id 
              WHERE 1=1";

$params = [];
$types = "";

// Add filters to the query
if (!empty($filterSeverity)) {
    $query .= " AND a.severity = ?";
    $countQuery .= " AND a.severity = ?";
    $params[] = $filterSeverity;
    $types .= "s";
}

if (!empty($filterStatus)) {
    $query .= " AND a.status = ?";
    $countQuery .= " AND a.status = ?";
    $params[] = $filterStatus;
    $types .= "s";
}

if (!empty($filterSourceIP)) {
    $query .= " AND e.source_ip = ?";
    $countQuery .= " AND e.source_ip = ?";
    $params[] = $filterSourceIP;
    $types .= "s";
}

if (!empty($filterRuleId)) {
    $query .= " AND a.rule_id = ?";
    $countQuery .= " AND a.rule_id = ?";
    $params[] = $filterRuleId;
    $types .= "i";
}

if (!empty($filterDateFrom)) {
    $query .= " AND a.created_at >= ?";
    $countQuery .= " AND a.created_at >= ?";
    $params[] = $filterDateFrom . " 00:00:00";
    $types .= "s";
}

if (!empty($filterDateTo)) {
    $query .= " AND a.created_at <= ?";
    $countQuery .= " AND a.created_at <= ?";
    $params[] = $filterDateTo . " 23:59:59";
    $types .= "s";
}

if (!empty($searchQuery)) {
    $query .= " AND (a.alert_message LIKE ? OR e.source_ip LIKE ? OR e.destination_ip LIKE ? OR r.rule_name LIKE ?)";
    $countQuery .= " AND (a.alert_message LIKE ? OR e.source_ip LIKE ? OR e.destination_ip LIKE ? OR r.rule_name LIKE ?)";
    $searchParam = "%" . $searchQuery . "%";
    $params[] = $searchParam;
    $params[] = $searchParam;
    $params[] = $searchParam;
    $params[] = $searchParam;
    $types .= "ssss";
}

// Add sorting and pagination
$query .= " ORDER BY a.created_at DESC LIMIT ? OFFSET ?";
$params[] = $limit;
$params[] = $offset;
$types .= "ii";

// Get total count for pagination
$countStmt = $conn->prepare($countQuery);
if (!empty($types)) {
    $countStmt->bind_param($types, ...$params);
}
$countStmt->execute();
$countResult = $countStmt->get_result();
$totalRows = $countResult->fetch_assoc()['total'];
$totalPages = ceil($totalRows / $limit);

// Get alerts
$stmt = $conn->prepare($query);
if (!empty($types)) {
    // Remove the last two parameters (limit and offset) since they're added separately
    $queryParams = array_slice($params, 0, -2);
    if (!empty($queryParams)) {
        $queryTypes = substr($types, 0, -2);
        $stmt->bind_param($queryTypes . "ii", ...$params);
    } else {
        $stmt->bind_param("ii", $params[count($params) - 2], $params[count($params) - 1]);
    }
} else {
    $stmt->bind_param("ii", $limit, $offset);
}
$stmt->execute();
$result = $stmt->get_result();
$alerts = [];
while ($row = $result->fetch_assoc()) {
    $alerts[] = $row;
}

// Get severity counts for filter
$severityCounts = [];
$query = "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity ORDER BY 
         FIELD(severity, 'critical', 'high', 'medium', 'low', 'informational')";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $severityCounts[$row['severity']] = $row['count'];
}

// Get status counts for filter
$statusCounts = [];
$query = "SELECT status, COUNT(*) as count FROM alerts GROUP BY status ORDER BY 
         FIELD(status, 'new', 'acknowledged', 'resolved', 'false_positive')";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $statusCounts[$row['status']] = $row['count'];
}

// Get rules for filter
$rules = [];
$query = "SELECT rule_id, rule_name FROM alert_rules ORDER BY rule_name";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $rules[$row['rule_id']] = $row['rule_name'];
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
    <title>Alerts - <?php echo SITE_NAME; ?></title>
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
                        <li class="breadcrumb-item active" aria-current="page">Alerts</li>
                    </ol>
                </nav>

                <?php if (isset($message)): ?>
                    <div class="alert alert-<?php echo $messageType; ?> alert-dismissible fade show" role="alert">
                        <?php echo $message; ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                <?php endif; ?>
                
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2"><i class="fas fa-bell"></i> Alerts</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <div class="btn-group me-2">
                            <button type="button" class="btn btn-sm btn-outline-secondary" id="refreshBtn">
                                <i class="fas fa-sync-alt"></i> Refresh
                            </button>
                            <button type="button" class="btn btn-sm btn-outline-secondary" data-bs-toggle="modal" data-bs-target="#exportModal">
                                <i class="fas fa-download"></i> Export
                            </button>
                        </div>
                        <div class="dropdown">
                            <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" id="bulkActionDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                                <i class="fas fa-cog"></i> Bulk Actions
                            </button>
                            <ul class="dropdown-menu" aria-labelledby="bulkActionDropdown">
                                <li><a class="dropdown-item bulk-action" href="#" data-action="acknowledge"><i class="fas fa-check-circle"></i> Acknowledge Selected</a></li>
                                <li><a class="dropdown-item bulk-action" href="#" data-action="resolve"><i class="fas fa-check-double"></i> Resolve Selected</a></li>
                                <li><a class="dropdown-item bulk-action" href="#" data-action="false_positive"><i class="fas fa-times-circle"></i> Mark as False Positive</a></li>
                            </ul>
                        </div>
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
                            <form action="alerts.php" method="get" id="filterForm">
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
                                            <option value="informational" <?php echo $filterSeverity === 'informational' ? 'selected' : ''; ?>>
                                                Informational (<?php echo isset($severityCounts['informational']) ? $severityCounts['informational'] : 0; ?>)
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
                                            <option value="acknowledged" <?php echo $filterStatus === 'acknowledged' ? 'selected' : ''; ?>>
                                                Acknowledged (<?php echo isset($statusCounts['acknowledged']) ? $statusCounts['acknowledged'] : 0; ?>)
                                            </option>
                                            <option value="resolved" <?php echo $filterStatus === 'resolved' ? 'selected' : ''; ?>>
                                                Resolved (<?php echo isset($statusCounts['resolved']) ? $statusCounts['resolved'] : 0; ?>)
                                            </option>
                                            <option value="false_positive" <?php echo $filterStatus === 'false_positive' ? 'selected' : ''; ?>>
                                                False Positive (<?php echo isset($statusCounts['false_positive']) ? $statusCounts['false_positive'] : 0; ?>)
                                            </option>
                                        </select>
                                    </div>
                                    <div class="col-md-3">
                                        <label for="rule_id" class="form-label">Rule</label>
                                        <select class="form-select" id="rule_id" name="rule_id">
                                            <option value="">All Rules</option>
                                            <?php foreach ($rules as $id => $name): ?>
                                                <option value="<?php echo $id; ?>" <?php echo $filterRuleId === $id ? 'selected' : ''; ?>>
                                                    <?php echo htmlspecialchars($name); ?>
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                    <div class="col-md-3">
                                        <label for="source_ip" class="form-label">Source IP</label>
                                        <input type="text" class="form-control" id="source_ip" name="source_ip" placeholder="e.g. 192.168.1.1" value="<?php echo htmlspecialchars($filterSourceIP); ?>">
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
                                        <input type="text" class="form-control" id="search" name="search" placeholder="Search alerts..." value="<?php echo htmlspecialchars($searchQuery); ?>">
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
                                        <a href="alerts.php" class="btn btn-outline-secondary">
                                            <i class="fas fa-undo"></i> Clear Filters
                                        </a>
                                    </div>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
                
                <!-- Alerts table -->
                <div class="card">
                    <div class="card-body p-0">
                        <form id="bulkActionForm" method="post">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                            <input type="hidden" name="action" id="bulkActionType" value="">
                            
                            <div class="table-responsive">
                                <table class="table table-hover align-middle mb-0">
                                    <thead class="table-light">
                                        <tr>
                                            <th style="width: 40px;">
                                                <div class="form-check">
                                                    <input class="form-check-input" type="checkbox" id="selectAll">
                                                </div>
                                            </th>
                                            <th style="width: 170px;">Time</th>
                                            <th style="width: 100px;">Severity</th>
                                            <th>Alert</th>
                                            <th style="width: 150px;">Source IP</th>
                                            <th style="width: 130px;">Status</th>
                                            <th style="width: 100px;">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php if (empty($alerts)): ?>
                                            <tr>
                                                <td colspan="7" class="text-center py-4">No alerts found matching your criteria</td>
                                            </tr>
                                        <?php else: ?>
                                            <?php foreach ($alerts as $alert): ?>
                                                <tr>
                                                    <td>
                                                        <div class="form-check">
                                                            <input class="form-check-input alert-checkbox" type="checkbox" name="selected_alerts[]" value="<?php echo $alert['alert_id']; ?>">
                                                        </div>
                                                    </td>
                                                    <td>
                                                        <div><?php echo date('Y-m-d', strtotime($alert['created_at'])); ?></div>
                                                        <small class="text-muted"><?php echo date('H:i:s', strtotime($alert['created_at'])); ?></small>
                                                    </td>
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
                                                    <td>
                                                        <a href="alert-details.php?id=<?php echo $alert['alert_id']; ?>" class="text-decoration-none">
                                                            <?php echo htmlspecialchars(substr($alert['alert_message'], 0, 100)) . (strlen($alert['alert_message']) > 100 ? '...' : ''); ?>
                                                        </a>
                                                        <?php if (!empty($alert['rule_name'])): ?>
                                                            <div class="small text-muted">Rule: <?php echo htmlspecialchars($alert['rule_name']); ?></div>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td>
                                                        <?php if (!empty($alert['source_ip'])): ?>
                                                            <a href="alerts.php?source_ip=<?php echo urlencode($alert['source_ip']); ?>" class="text-decoration-none">
                                                                <?php echo htmlspecialchars($alert['source_ip']); ?>
                                                            </a>
                                                        <?php else: ?>
                                                            <span class="text-muted">N/A</span>
                                                        <?php endif; ?>
                                                    </td>
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
                                                        <?php if (!empty($alert['acknowledged_by'])): ?>
                                                            <div class="small text-muted">by: <?php echo htmlspecialchars($alert['acknowledged_by']); ?></div>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td>
                                                        <div class="dropdown">
                                                            <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" id="actionDropdown<?php echo $alert['alert_id']; ?>" data-bs-toggle="dropdown" aria-expanded="false">
                                                                <i class="fas fa-ellipsis-v"></i>
                                                            </button>
                                                            <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="actionDropdown<?php echo $alert['alert_id']; ?>">
                                                                <li><a class="dropdown-item" href="alert-details.php?id=<?php echo $alert['alert_id']; ?>"><i class="fas fa-eye"></i> View Details</a></li>
                                                                <?php if ($alert['status'] === 'new'): ?>
                                                                    <li><a class="dropdown-item single-action" href="#" data-id="<?php echo $alert['alert_id']; ?>" data-action="acknowledge"><i class="fas fa-check-circle"></i> Acknowledge</a></li>
                                                                <?php endif; ?>
                                                                <?php if ($alert['status'] !== 'resolved' && $alert['status'] !== 'false_positive'): ?>
                                                                    <li><a class="dropdown-item single-action" href="#" data-id="<?php echo $alert['alert_id']; ?>" data-action="resolve"><i class="fas fa-check-double"></i> Resolve</a></li>
                                                                    <li><a class="dropdown-item single-action" href="#" data-id="<?php echo $alert['alert_id']; ?>" data-action="false_positive"><i class="fas fa-times-circle"></i> False Positive</a></li>
                                                                <?php endif; ?>
                                                                <li><hr class="dropdown-divider"></li>
                                                                <li><a class="dropdown-item" href="#" data-bs-toggle="modal" data-bs-target="#createIncidentModal" data-alert-id="<?php echo $alert['alert_id']; ?>"><i class="fas fa-file-alt"></i> Create Incident</a></li>
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
                                    Showing <?php echo $offset + 1; ?> to <?php echo min($offset + $limit, $totalRows); ?> of <?php echo $totalRows; ?> alerts
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
    
    <!-- Export Modal -->
    <div class="modal fade" id="exportModal" tabindex="-1" aria-labelledby="exportModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <form action="export-alerts.php" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="exportModalLabel">Export Alerts</h5>
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
                                <option value="filtered">Current filtered results (<?php echo $totalRows; ?> alerts)</option>
                                <option value="selected">Selected alerts only</option>
                                <option value="all">All alerts</option>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="include_raw_logs" name="include_raw_logs" value="1">
                                <label class="form-check-label" for="include_raw_logs">
                                    Include raw log data
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
        <input type="hidden" name="selected_alerts[]" id="singleActionId" value="">
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
                document.querySelectorAll('.alert-checkbox').forEach(function(checkbox) {
                    checkbox.checked = isChecked;
                });
            });
            
            // Bulk actions
            document.querySelectorAll('.bulk-action').forEach(function(button) {
                button.addEventListener('click', function(e) {
                    e.preventDefault();
                    
                    // Check if any alerts are selected
                    const checkedBoxes = document.querySelectorAll('.alert-checkbox:checked');
                    if (checkedBoxes.length === 0) {
                        alert('Please select at least one alert.');
                        return;
                    }
                    
                    // Set the action type
                    const action = this.getAttribute('data-action');
                    document.getElementById('bulkActionType').value = action;
                    
                    // Confirm before submission
                    let actionText = '';
                    switch (action) {
                        case 'acknowledge':
                            actionText = 'acknowledge';
                            break;
                        case 'resolve':
                            actionText = 'resolve';
                            break;
                        case 'false_positive':
                            actionText = 'mark as false positive';
                            break;
                    }
                    
                    if (confirm(`Are you sure you want to ${actionText} ${checkedBoxes.length} alert(s)?`)) {
                        document.getElementById('bulkActionForm').submit();
                    }
                });
            });
            
            // Single actions
            document.querySelectorAll('.single-action').forEach(function(button) {
                button.addEventListener('click', function(e) {
                    e.preventDefault();
                    
                    const alertId = this.getAttribute('data-id');
                    const action = this.getAttribute('data-action');
                    
                    document.getElementById('singleActionType').value = action;
                    document.getElementById('singleActionId').value = alertId;
                    
                    // Confirm before submission
                    let actionText = '';
                    switch (action) {
                        case 'acknowledge':
                            actionText = 'acknowledge';
                            break;
                        case 'resolve':
                            actionText = 'resolve';
                            break;
                        case 'false_positive':
                            actionText = 'mark as false positive';
                            break;
                    }
                    
                    if (confirm(`Are you sure you want to ${actionText} this alert?`)) {
                        document.getElementById('singleActionForm').submit();
                    }
                });
            });
            
            // Refresh button
            document.getElementById('refreshBtn').addEventListener('click', function() {
                window.location.reload();
            });
        });
    </script>
</body>
</html>