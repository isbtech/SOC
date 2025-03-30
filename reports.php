<?php
require_once 'config.php';

// Initialize secure session
initSecureSession();

// Check if user is authenticated, redirect to login if not
if (!isAuthenticated()) {
    header("Location: index.php");
    exit;
}

// Generate CSRF token for forms
$csrfToken = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reports - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="assets/css/style.css">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
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
                        <li class="breadcrumb-item active" aria-current="page">Reports</li>
                    </ol>
                </nav>
                
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2"><i class="fas fa-chart-bar"></i> Reports</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <button type="button" class="btn btn-sm btn-outline-secondary me-2" id="refreshBtn">
                            <i class="fas fa-sync-alt"></i> Refresh
                        </button>
                        <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#newReportModal">
                            <i class="fas fa-plus"></i> New Report
                        </button>
                    </div>
                </div>
                
                <!-- Report Categories -->
                <div class="row mb-4">
                    <div class="col-md-4 mb-3">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title"><i class="fas fa-bell me-2"></i>Alerts Reports</h5>
                                <p class="card-text">View and generate reports about security alerts.</p>
                                <a href="#alerts-reports" class="btn btn-outline-primary">View Reports</a>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-4 mb-3">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title"><i class="fas fa-file-alt me-2"></i>Incident Reports</h5>
                                <p class="card-text">View and generate reports about security incidents.</p>
                                <a href="#incident-reports" class="btn btn-outline-primary">View Reports</a>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-4 mb-3">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title"><i class="fas fa-bug me-2"></i>Vulnerability Reports</h5>
                                <p class="card-text">View and generate reports about vulnerabilities.</p>
                                <a href="#vulnerability-reports" class="btn btn-outline-primary">View Reports</a>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Scheduled Reports -->
                <div class="card mb-4">
                    <div class="card-header bg-white d-flex justify-content-between align-items-center">
                        <h5 class="card-title mb-0">Scheduled Reports</h5>
                        <button type="button" class="btn btn-sm btn-outline-primary" data-bs-toggle="modal" data-bs-target="#scheduleReportModal">
                            <i class="fas fa-calendar-alt"></i> Schedule New
                        </button>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-hover table-striped mb-0">
                                <thead class="table-light">
                                    <tr>
                                        <th>Report Name</th>
                                        <th>Type</th>
                                        <th>Frequency</th>
                                        <th>Recipients</th>
                                        <th>Last Run</th>
                                        <th>Status</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td>Weekly Security Summary</td>
                                        <td>Summary</td>
                                        <td>Weekly (Monday)</td>
                                        <td>3 recipients</td>
                                        <td>N/A</td>
                                        <td><span class="badge bg-secondary">Not Run</span></td>
                                        <td>
                                            <div class="btn-group btn-group-sm">
                                                <button type="button" class="btn btn-outline-primary"><i class="fas fa-play"></i></button>
                                                <button type="button" class="btn btn-outline-secondary"><i class="fas fa-edit"></i></button>
                                                <button type="button" class="btn btn-outline-danger"><i class="fas fa-trash-alt"></i></button>
                                            </div>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td>Monthly Executive Report</td>
                                        <td>Executive</td>
                                        <td>Monthly (1st)</td>
                                        <td>2 recipients</td>
                                        <td>N/A</td>
                                        <td><span class="badge bg-secondary">Not Run</span></td>
                                        <td>
                                            <div class="btn-group btn-group-sm">
                                                <button type="button" class="btn btn-outline-primary"><i class="fas fa-play"></i></button>
                                                <button type="button" class="btn btn-outline-secondary"><i class="fas fa-edit"></i></button>
                                                <button type="button" class="btn btn-outline-danger"><i class="fas fa-trash-alt"></i></button>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
                <!-- Recent Reports -->
                <div class="card mb-4">
                    <div class="card-header bg-white">
                        <h5 class="card-title mb-0">Recent Reports</h5>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-hover table-striped mb-0">
                                <thead class="table-light">
                                    <tr>
                                        <th>Report Name</th>
                                        <th>Type</th>
                                        <th>Created By</th>
                                        <th>Created At</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr class="text-center">
                                        <td colspan="5" class="py-4 text-muted">No reports have been generated yet</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
                <!-- Report Templates -->
                <div class="card">
                    <div class="card-header bg-white">
                        <h5 class="card-title mb-0">Available Report Templates</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-4 mb-3">
                                <div class="card h-100">
                                    <div class="card-body">
                                        <h6 class="card-title">Security Summary Report</h6>
                                        <p class="card-text small">A comprehensive overview of security posture including alerts, incidents, and vulnerabilities.</p>
                                        <button type="button" class="btn btn-sm btn-outline-primary">Generate</button>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4 mb-3">
                                <div class="card h-100">
                                    <div class="card-body">
                                        <h6 class="card-title">Executive Dashboard</h6>
                                        <p class="card-text small">High-level security metrics and KPIs for executive review.</p>
                                        <button type="button" class="btn btn-sm btn-outline-primary">Generate</button>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4 mb-3">
                                <div class="card h-100">
                                    <div class="card-body">
                                        <h6 class="card-title">Compliance Report</h6>
                                        <p class="card-text small">Security compliance status and metrics for regulatory requirements.</p>
                                        <button type="button" class="btn btn-sm btn-outline-primary">Generate</button>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4 mb-3">
                                <div class="card h-100">
                                    <div class="card-body">
                                        <h6 class="card-title">Incident Response Summary</h6>
                                        <p class="card-text small">Summary of incident response activities and metrics.</p>
                                        <button type="button" class="btn btn-sm btn-outline-primary">Generate</button>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4 mb-3">
                                <div class="card h-100">
                                    <div class="card-body">
                                        <h6 class="card-title">Vulnerability Assessment</h6>
                                        <p class="card-text small">Detailed analysis of vulnerabilities across assets.</p>
                                        <button type="button" class="btn btn-sm btn-outline-primary">Generate</button>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4 mb-3">
                                <div class="card h-100">
                                    <div class="card-body">
                                        <h6 class="card-title">Custom Report</h6>
                                        <p class="card-text small">Create a custom report with selected metrics and data.</p>
                                        <button type="button" class="btn btn-sm btn-outline-primary">Create</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>
    
    <!-- New Report Modal -->
    <div class="modal fade" id="newReportModal" tabindex="-1" aria-labelledby="newReportModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="newReportModalLabel">Generate New Report</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form method="post" action="#">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                        <input type="hidden" name="action" value="generate_report">
                        
                        <div class="mb-3">
                            <label for="report_template" class="form-label">Report Template</label>
                            <select class="form-select" id="report_template" name="report_template" required>
                                <option value="">-- Select Template --</option>
                                <option value="security_summary">Security Summary Report</option>
                                <option value="executive_dashboard">Executive Dashboard</option>
                                <option value="compliance_report">Compliance Report</option>
                                <option value="incident_response">Incident Response Summary</option>
                                <option value="vulnerability_assessment">Vulnerability Assessment</option>
                                <option value="custom">Custom Report</option>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <label for="report_name" class="form-label">Report Name</label>
                            <input type="text" class="form-control" id="report_name" name="report_name" required>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="date_from" class="form-label">Date From</label>
                                <input type="date" class="form-control" id="date_from" name="date_from" required>
                            </div>
                            <div class="col-md-6">
                                <label for="date_to" class="form-label">Date To</label>
                                <input type="date" class="form-control" id="date_to" name="date_to" required>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="report_format" class="form-label">Format</label>
                            <select class="form-select" id="report_format" name="report_format" required>
                                <option value="pdf">PDF</option>
                                <option value="html">HTML</option>
                                <option value="csv">CSV</option>
                                <option value="excel">Excel</option>
                            </select>
                        </div>
                        
                        <div class="form-check form-switch mb-3">
                            <input class="form-check-input" type="checkbox" id="include_charts" name="include_charts" checked>
                            <label class="form-check-label" for="include_charts">Include Charts and Graphs</label>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary">Generate Report</button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Schedule Report Modal -->
    <div class="modal fade" id="scheduleReportModal" tabindex="-1" aria-labelledby="scheduleReportModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="scheduleReportModalLabel">Schedule Report</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form method="post" action="#">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                        <input type="hidden" name="action" value="schedule_report">
                        
                        <div class="mb-3">
                            <label for="schedule_template" class="form-label">Report Template</label>
                            <select class="form-select" id="schedule_template" name="schedule_template" required>
                                <option value="">-- Select Template --</option>
                                <option value="security_summary">Security Summary Report</option>
                                <option value="executive_dashboard">Executive Dashboard</option>
                                <option value="compliance_report">Compliance Report</option>
                                <option value="incident_response">Incident Response Summary</option>
                                <option value="vulnerability_assessment">Vulnerability Assessment</option>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <label for="schedule_name" class="form-label">Schedule Name</label>
                            <input type="text" class="form-control" id="schedule_name" name="schedule_name" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="frequency" class="form-label">Frequency</label>
                            <select class="form-select" id="frequency" name="frequency" required>
                                <option value="daily">Daily</option>
                                <option value="weekly">Weekly</option>
                                <option value="monthly">Monthly</option>
                                <option value="quarterly">Quarterly</option>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <label for="schedule_time" class="form-label">Time</label>
                            <input type="time" class="form-control" id="schedule_time" name="schedule_time" value="08:00" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="report_format" class="form-label">Format</label>
                            <select class="form-select" id="report_format" name="report_format" required>
                                <option value="pdf">PDF</option>
                                <option value="html">HTML</option>
                                <option value="csv">CSV</option>
                                <option value="excel">Excel</option>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <label for="recipients" class="form-label">Recipients (Email)</label>
                            <textarea class="form-control" id="recipients" name="recipients" rows="3" placeholder="Enter email addresses separated by commas"></textarea>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary">Schedule Report</button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Include footer -->
    <?php include 'includes/footer.php'; ?>
    
    <!-- Include JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>