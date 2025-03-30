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

// Get user information
$userId = $_SESSION['user_id'];
$stmt = $conn->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
$stmt->bind_param("i", $userId);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();
$fullName = $user['first_name'] . ' ' . $user['last_name'];

// Get alert statistics
$alertStats = [];
$query = "SELECT severity, COUNT(*) as count FROM alerts WHERE status = 'new' GROUP BY severity ORDER BY 
          FIELD(severity, 'critical', 'high', 'medium', 'low', 'informational')";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $alertStats[$row['severity']] = $row['count'];
}

// Get incident statistics
$incidentStats = [];
$query = "SELECT status, COUNT(*) as count FROM incidents WHERE status != 'closed' GROUP BY status ORDER BY 
          FIELD(status, 'new', 'assigned', 'investigating', 'contained', 'remediated')";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $incidentStats[$row['status']] = $row['count'];
}

// Get recent alerts (limited to 10)
$recentAlerts = [];
$query = "SELECT a.alert_id, a.alert_message, a.severity, a.created_at, a.status, r.rule_name 
          FROM alerts a 
          LEFT JOIN alert_rules r ON a.rule_id = r.rule_id 
          ORDER BY a.created_at DESC LIMIT 10";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $recentAlerts[] = $row;
}

// Get recent incidents (limited to 10)
$recentIncidents = [];
$query = "SELECT i.incident_id, i.title, i.severity, i.status, i.created_at, u.username as assigned_to 
          FROM incidents i 
          LEFT JOIN users u ON i.assigned_to = u.user_id 
          ORDER BY i.created_at DESC LIMIT 10";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $recentIncidents[] = $row;
}

// Get asset counts by criticality
$assetStats = [];
$query = "SELECT criticality, COUNT(*) as count FROM assets GROUP BY criticality ORDER BY 
          FIELD(criticality, 'critical', 'high', 'medium', 'low')";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $assetStats[$row['criticality']] = $row['count'];
}

// Get vulnerability statistics
$vulnStats = [];
$query = "SELECT severity, COUNT(*) as count FROM vulnerabilities WHERE status = 'open' GROUP BY severity ORDER BY 
          FIELD(severity, 'critical', 'high', 'medium', 'low', 'informational')";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $vulnStats[$row['severity']] = $row['count'];
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
    <title>Dashboard - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="assets/css/style.css">
    <!-- Include modern UI framework CSS (Bootstrap, etc.) -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Include Font Awesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- Include Chart.js for visualization -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="bg-light">
    <!-- Include header/navigation -->
    <?php include 'includes/header.php'; ?>
    
    <div class="container-fluid">
        <div class="row">
            <!-- Include sidebar -->
            <?php include 'includes/sidebar.php'; ?>
            
            <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4 py-4">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2"><i class="fas fa-tachometer-alt"></i> Security Dashboard</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <div class="dropdown">
                            <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" id="timeRangeDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                                <i class="fas fa-calendar"></i> Last 24 hours
                            </button>
                            <ul class="dropdown-menu" aria-labelledby="timeRangeDropdown">
                                <li><a class="dropdown-item" href="#">Last 24 hours</a></li>
                                <li><a class="dropdown-item" href="#">Last 7 days</a></li>
                                <li><a class="dropdown-item" href="#">Last 30 days</a></li>
                                <li><a class="dropdown-item" href="#">Custom range</a></li>
                            </ul>
                        </div>
                
            </main>
        </div>
    </div>
    
    <!-- Include footer -->
    <?php include 'includes/footer.php'; ?>
    
    <!-- JavaScript for Charts -->
    <script>
        // Alert Severity Distribution Chart
        const alertSeverityCtx = document.getElementById('alertSeverityChart').getContext('2d');
        const alertSeverityChart = new Chart(alertSeverityCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Informational'],
                datasets: [{
                    data: [
                        <?php echo isset($alertStats['critical']) ? $alertStats['critical'] : 0; ?>,
                        <?php echo isset($alertStats['high']) ? $alertStats['high'] : 0; ?>,
                        <?php echo isset($alertStats['medium']) ? $alertStats['medium'] : 0; ?>,
                        <?php echo isset($alertStats['low']) ? $alertStats['low'] : 0; ?>,
                        <?php echo isset($alertStats['informational']) ? $alertStats['informational'] : 0; ?>
                    ],
                    backgroundColor: [
                        '#dc3545', // Critical - Danger
                        '#ffc107', // High - Warning
                        '#0d6efd', // Medium - Primary
                        '#198754', // Low - Success
                        '#0dcaf0'  // Informational - Info
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                    }
                }
            }
        });
        
        // Incident Status Chart
        const incidentStatusCtx = document.getElementById('incidentStatusChart').getContext('2d');
        const incidentStatusChart = new Chart(incidentStatusCtx, {
            type: 'pie',
            data: {
                labels: ['New', 'Assigned', 'Investigating', 'Contained', 'Remediated'],
                datasets: [{
                    data: [
                        <?php echo isset($incidentStats['new']) ? $incidentStats['new'] : 0; ?>,
                        <?php echo isset($incidentStats['assigned']) ? $incidentStats['assigned'] : 0; ?>,
                        <?php echo isset($incidentStats['investigating']) ? $incidentStats['investigating'] : 0; ?>,
                        <?php echo isset($incidentStats['contained']) ? $incidentStats['contained'] : 0; ?>,
                        <?php echo isset($incidentStats['remediated']) ? $incidentStats['remediated'] : 0; ?>
                    ],
                    backgroundColor: [
                        '#dc3545', // New - Danger
                        '#ffc107', // Assigned - Warning
                        '#0dcaf0', // Investigating - Info
                        '#0d6efd', // Contained - Primary
                        '#198754'  // Remediated - Success
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                    }
                }
            }
        });
        
        // Asset Criticality Chart
        const assetCriticalityCtx = document.getElementById('assetCriticalityChart').getContext('2d');
        const assetCriticalityChart = new Chart(assetCriticalityCtx, {
            type: 'bar',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    label: 'Asset Count',
                    data: [
                        <?php echo isset($assetStats['critical']) ? $assetStats['critical'] : 0; ?>,
                        <?php echo isset($assetStats['high']) ? $assetStats['high'] : 0; ?>,
                        <?php echo isset($assetStats['medium']) ? $assetStats['medium'] : 0; ?>,
                        <?php echo isset($assetStats['low']) ? $assetStats['low'] : 0; ?>
                    ],
                    backgroundColor: [
                        '#dc3545', // Critical - Danger
                        '#ffc107', // High - Warning
                        '#0d6efd', // Medium - Primary
                        '#198754'  // Low - Success
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // Vulnerability Severity Chart
        const vulnerabilitySeverityCtx = document.getElementById('vulnerabilitySeverityChart').getContext('2d');
        const vulnerabilitySeverityChart = new Chart(vulnerabilitySeverityCtx, {
            type: 'bar',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Informational'],
                datasets: [{
                    label: 'Vulnerability Count',
                    data: [
                        <?php echo isset($vulnStats['critical']) ? $vulnStats['critical'] : 0; ?>,
                        <?php echo isset($vulnStats['high']) ? $vulnStats['high'] : 0; ?>,
                        <?php echo isset($vulnStats['medium']) ? $vulnStats['medium'] : 0; ?>,
                        <?php echo isset($vulnStats['low']) ? $vulnStats['low'] : 0; ?>,
                        <?php echo isset($vulnStats['informational']) ? $vulnStats['informational'] : 0; ?>
                    ],
                    backgroundColor: [
                        '#dc3545', // Critical - Danger
                        '#ffc107', // High - Warning
                        '#0d6efd', // Medium - Primary
                        '#198754', // Low - Success
                        '#0dcaf0'  // Informational - Info
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // Refresh dashboard
        document.getElementById('refreshDashboard').addEventListener('click', function() {
            location.reload();
        });
    </script>
</body>
</html>
                
                <!-- Charts and Activity Section -->
                <div class="row mb-4">
                    <!-- Alert Severity Distribution Chart -->
                    <div class="col-md-6">
                        <div class="card h-100">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0">Alert Severity Distribution</h5>
                            </div>
                            <div class="card-body">
                                <canvas id="alertSeverityChart" width="400" height="250"></canvas>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Incident Status Chart -->
                    <div class="col-md-6">
                        <div class="card h-100">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0">Incident Status</h5>
                            </div>
                            <div class="card-body">
                                <canvas id="incidentStatusChart" width="400" height="250"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Recent Activity Section -->
                <div class="row">
                    <!-- Recent Alerts -->
                    <div class="col-md-6 mb-4">
                        <div class="card">
                            <div class="card-header d-flex justify-content-between align-items-center bg-white">
                                <h5 class="card-title mb-0">Recent Alerts</h5>
                                <a href="alerts.php" class="btn btn-sm btn-outline-primary">View All</a>
                            </div>
                            <div class="card-body p-0">
                                <div class="table-responsive">
                                    <table class="table table-hover table-striped align-middle mb-0">
                                        <thead class="table-light">
                                            <tr>
                                                <th scope="col">Severity</th>
                                                <th scope="col">Alert</th>
                                                <th scope="col">Time</th>
                                                <th scope="col">Status</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php if (empty($recentAlerts)): ?>
                                                <tr>
                                                    <td colspan="4" class="text-center py-3">No recent alerts</td>
                                                </tr>
                                            <?php else: ?>
                                                <?php foreach ($recentAlerts as $alert): ?>
                                                    <tr>
                                                        <td>
                                                            <?php 
                                                            $severityClass = '';
                                                            switch ($alert['severity']) {
                                                                case 'critical':
                                                                    $severityClass = 'bg-danger';
                                                                    break;
                                                                case 'high':
                                                                    $severityClass = 'bg-warning text-dark';
                                                                    break;
                                                                case 'medium':
                                                                    $severityClass = 'bg-primary';
                                                                    break;
                                                                case 'low':
                                                                    $severityClass = 'bg-success';
                                                                    break;
                                                                default:
                                                                    $severityClass = 'bg-info';
                                                            }
                                                            ?>
                                                            <span class="badge <?php echo $severityClass; ?>"><?php echo ucfirst($alert['severity']); ?></span>
                                                        </td>
                                                        <td>
                                                            <a href="alert-details.php?id=<?php echo $alert['alert_id']; ?>" class="text-decoration-none">
                                                                <?php echo htmlspecialchars(substr($alert['alert_message'], 0, 50)) . (strlen($alert['alert_message']) > 50 ? '...' : ''); ?>
                                                            </a>
                                                            <div class="small text-muted"><?php echo $alert['rule_name']; ?></div>
                                                        </td>
                                                        <td>
                                                            <span class="small">
                                                                <?php 
                                                                $timestamp = strtotime($alert['created_at']);
                                                                echo date('M d, H:i', $timestamp); 
                                                                ?>
                                                            </span>
                                                        </td>
                                                        <td>
                                                            <?php 
                                                            $statusClass = '';
                                                            switch ($alert['status']) {
                                                                case 'new':
                                                                    $statusClass = 'bg-danger';
                                                                    break;
                                                                case 'acknowledged':
                                                                    $statusClass = 'bg-warning text-dark';
                                                                    break;
                                                                case 'resolved':
                                                                    $statusClass = 'bg-success';
                                                                    break;
                                                                default:
                                                                    $statusClass = 'bg-secondary';
                                                            }
                                                            ?>
                                                            <span class="badge <?php echo $statusClass; ?>"><?php echo ucfirst($alert['status']); ?></span>
                                                        </td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            <?php endif; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Recent Incidents -->
                    <div class="col-md-6 mb-4">
                        <div class="card">
                            <div class="card-header d-flex justify-content-between align-items-center bg-white">
                                <h5 class="card-title mb-0">Recent Incidents</h5>
                                <a href="incidents.php" class="btn btn-sm btn-outline-primary">View All</a>
                            </div>
                            <div class="card-body p-0">
                                <div class="table-responsive">
                                    <table class="table table-hover table-striped align-middle mb-0">
                                        <thead class="table-light">
                                            <tr>
                                                <th scope="col">Severity</th>
                                                <th scope="col">Title</th>
                                                <th scope="col">Status</th>
                                                <th scope="col">Assigned To</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php if (empty($recentIncidents)): ?>
                                                <tr>
                                                    <td colspan="4" class="text-center py-3">No recent incidents</td>
                                                </tr>
                                            <?php else: ?>
                                                <?php foreach ($recentIncidents as $incident): ?>
                                                    <tr>
                                                        <td>
                                                            <?php 
                                                            $severityClass = '';
                                                            switch ($incident['severity']) {
                                                                case 'critical':
                                                                    $severityClass = 'bg-danger';
                                                                    break;
                                                                case 'high':
                                                                    $severityClass = 'bg-warning text-dark';
                                                                    break;
                                                                case 'medium':
                                                                    $severityClass = 'bg-primary';
                                                                    break;
                                                                default:
                                                                    $severityClass = 'bg-success';
                                                            }
                                                            ?>
                                                            <span class="badge <?php echo $severityClass; ?>"><?php echo ucfirst($incident['severity']); ?></span>
                                                        </td>
                                                        <td>
                                                            <a href="incident-details.php?id=<?php echo $incident['incident_id']; ?>" class="text-decoration-none">
                                                                <?php echo htmlspecialchars(substr($incident['title'], 0, 50)) . (strlen($incident['title']) > 50 ? '...' : ''); ?>
                                                            </a>
                                                            <div class="small text-muted">
                                                                <?php 
                                                                $timestamp = strtotime($incident['created_at']);
                                                                echo date('M d, H:i', $timestamp); 
                                                                ?>
                                                            </div>
                                                        </td>
                                                        <td>
                                                            <?php 
                                                            $statusClass = '';
                                                            switch ($incident['status']) {
                                                                case 'new':
                                                                    $statusClass = 'bg-danger';
                                                                    break;
                                                                case 'assigned':
                                                                    $statusClass = 'bg-warning text-dark';
                                                                    break;
                                                                case 'investigating':
                                                                    $statusClass = 'bg-info';
                                                                    break;
                                                                case 'contained':
                                                                    $statusClass = 'bg-primary';
                                                                    break;
                                                                case 'remediated':
                                                                    $statusClass = 'bg-success';
                                                                    break;
                                                                default:
                                                                    $statusClass = 'bg-secondary';
                                                            }
                                                            ?>
                                                            <span class="badge <?php echo $statusClass; ?>"><?php echo ucfirst($incident['status']); ?></span>
                                                        </td>
                                                        <td>
                                                            <?php if (!empty($incident['assigned_to'])): ?>
                                                                <span class="badge bg-secondary"><?php echo htmlspecialchars($incident['assigned_to']); ?></span>
                                                            <?php else: ?>
                                                                <span class="badge bg-light text-dark">Unassigned</span>
                                                            <?php endif; ?>
                                                        </td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            <?php endif; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Asset and Vulnerability Section -->
                <div class="row">
                    <!-- Asset Distribution Chart -->
                    <div class="col-md-6 mb-4">
                        <div class="card h-100">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0">Asset Criticality Distribution</h5>
                            </div>
                            <div class="card-body">
                                <canvas id="assetCriticalityChart" width="400" height="250"></canvas>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Vulnerability Distribution Chart -->
                    <div class="col-md-6 mb-4">
                        <div class="card h-100">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0">Open Vulnerabilities by Severity</h5>
                            </div>
                            <div class="card-body">
                                <canvas id="vulnerabilitySeverityChart" width="400" height="250"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
                        <button type="button" class="btn btn-sm btn-outline-secondary ms-2" id="refreshDashboard">
                            <i class="fas fa-sync-alt"></i> Refresh
                        </button>
                    </div>
                </div>
                
                <!-- Alert Summary Cards -->
                <div class="row g-3 mb-4">
                    <!-- Critical Alerts -->
                    <div class="col-md-3">
                        <div class="card bg-danger text-white h-100">
                            <div class="card-body py-3">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="card-title mb-0">Critical Alerts</h6>
                                        <h2 class="mt-2 mb-0"><?php echo isset($alertStats['critical']) ? $alertStats['critical'] : 0; ?></h2>
                                    </div>
                                    <i class="fas fa-exclamation-circle fa-2x"></i>
                                </div>
                            </div>
                            <div class="card-footer d-flex align-items-center justify-content-between bg-danger-dark">
                                <a href="alerts.php?severity=critical" class="text-white text-decoration-none small">View details</a>
                                <i class="fas fa-arrow-circle-right text-white"></i>
                            </div>
                        </div>
                    </div>
                    
                    <!-- High Alerts -->
                    <div class="col-md-3">
                        <div class="card bg-warning text-dark h-100">
                            <div class="card-body py-3">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="card-title mb-0">High Alerts</h6>
                                        <h2 class="mt-2 mb-0"><?php echo isset($alertStats['high']) ? $alertStats['high'] : 0; ?></h2>
                                    </div>
                                    <i class="fas fa-exclamation-triangle fa-2x"></i>
                                </div>
                            </div>
                            <div class="card-footer d-flex align-items-center justify-content-between bg-warning-dark">
                                <a href="alerts.php?severity=high" class="text-dark text-decoration-none small">View details</a>
                                <i class="fas fa-arrow-circle-right text-dark"></i>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Active Incidents -->
                    <div class="col-md-3">
                        <div class="card bg-primary text-white h-100">
                            <div class="card-body py-3">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="card-title mb-0">Active Incidents</h6>
                                        <h2 class="mt-2 mb-0"><?php echo array_sum($incidentStats); ?></h2>
                                    </div>
                                    <i class="fas fa-file-alt fa-2x"></i>
                                </div>
                            </div>
                            <div class="card-footer d-flex align-items-center justify-content-between bg-primary-dark">
                                <a href="incidents.php" class="text-white text-decoration-none small">View details</a>
                                <i class="fas fa-arrow-circle-right text-white"></i>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Open Vulnerabilities -->
                    <div class="col-md-3">
                        <div class="card bg-info text-white h-100">
                            <div class="card-body py-3">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="card-title mb-0">Open Vulnerabilities</h6>
                                        <h2 class="mt-2 mb-0"><?php echo array_sum($vulnStats); ?></h2>
                                    </div>
                                    <i class="fas fa-bug fa-2x"></i>
                                </div>
                            </div>
                            <div class="card-footer d-flex align-items-center justify-content-between bg-info-dark">
                                <a href="vulnerabilities.php" class="text-white text-decoration-none small">View details</a>
                                <i class="fas fa-arrow-circle-right text-white"></i>
                            </div>
                        </div>
                    </div>
                </div>