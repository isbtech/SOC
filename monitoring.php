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
    <title>Monitoring - <?php echo SITE_NAME; ?></title>
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
                        <li class="breadcrumb-item active" aria-current="page">Monitoring</li>
                    </ol>
                </nav>
                
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2"><i class="fas fa-desktop"></i> Real-time Monitoring</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <div class="btn-group me-2">
                            <button type="button" class="btn btn-sm btn-outline-secondary" id="refreshBtn">
                                <i class="fas fa-sync-alt"></i> Refresh
                            </button>
                            <button type="button" class="btn btn-sm btn-outline-secondary" data-bs-toggle="modal" data-bs-target="#monitoringSettingsModal">
                                <i class="fas fa-cog"></i> Settings
                            </button>
                        </div>
                        <button type="button" class="btn btn-sm btn-primary">
                            <i class="fas fa-plus"></i> Add Monitor
                        </button>
                    </div>
                </div>
                
                <!-- Alert Stats -->
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="card bg-danger text-white h-100">
                            <div class="card-body d-flex align-items-center justify-content-between">
                                <div>
                                    <h6 class="card-title mb-0">Critical Alerts</h6>
                                    <h2 class="mt-2 mb-0">0</h2>
                                </div>
                                <i class="fas fa-exclamation-circle fa-2x"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-warning text-dark h-100">
                            <div class="card-body d-flex align-items-center justify-content-between">
                                <div>
                                    <h6 class="card-title mb-0">High Alerts</h6>
                                    <h2 class="mt-2 mb-0">0</h2>
                                </div>
                                <i class="fas fa-exclamation-triangle fa-2x"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-primary text-white h-100">
                            <div class="card-body d-flex align-items-center justify-content-between">
                                <div>
                                    <h6 class="card-title mb-0">Active Monitors</h6>
                                    <h2 class="mt-2 mb-0">12</h2>
                                </div>
                                <i class="fas fa-tv fa-2x"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-success text-white h-100">
                            <div class="card-body d-flex align-items-center justify-content-between">
                                <div>
                                    <h6 class="card-title mb-0">Healthy Systems</h6>
                                    <h2 class="mt-2 mb-0">12</h2>
                                </div>
                                <i class="fas fa-check-circle fa-2x"></i>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Network Monitoring -->
                <div class="card mb-4">
                    <div class="card-header bg-white d-flex justify-content-between align-items-center">
                        <h5 class="card-title mb-0">Network Monitoring</h5>
                        <span class="badge bg-success">All Systems Operational</span>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-hover table-striped mb-0">
                                <thead class="table-light">
                                    <tr>
                                        <th>Device</th>
                                        <th>IP Address</th>
                                        <th>Status</th>
                                        <th>Latency</th>
                                        <th>Packet Loss</th>
                                        <th>Last Check</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td>Main Router</td>
                                        <td>192.168.1.1</td>
                                        <td><span class="badge bg-success">Online</span></td>
                                        <td>2ms</td>
                                        <td>0%</td>
                                        <td>Just now</td>
                                        <td>
                                            <div class="btn-group btn-group-sm">
                                                <button type="button" class="btn btn-outline-primary"><i class="fas fa-chart-line"></i></button>
                                                <button type="button" class="btn btn-outline-secondary"><i class="fas fa-cog"></i></button>
                                                <button type="button" class="btn btn-outline-danger"><i class="fas fa-pause"></i></button>
                                            </div>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td>Core Switch</td>
                                        <td>192.168.1.2</td>
                                        <td><span class="badge bg-success">Online</span></td>
                                        <td>1ms</td>
                                        <td>0%</td>
                                        <td>Just now</td>
                                        <td>
                                            <div class="btn-group btn-group-sm">
                                                <button type="button" class="btn btn-outline-primary"><i class="fas fa-chart-line"></i></button>
                                                <button type="button" class="btn btn-outline-secondary"><i class="fas fa-cog"></i></button>
                                                <button type="button" class="btn btn-outline-danger"><i class="fas fa-pause"></i></button>
                                            </div>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td>Firewall</td>
                                        <td>192.168.1.3</td>
                                        <td><span class="badge bg-success">Online</span></td>
                                        <td>3ms</td>
                                        <td>0%</td>
                                        <td>Just now</td>
                                        <td>
                                            <div class="btn-group btn-group-sm">
                                                <button type="button" class="btn btn-outline-primary"><i class="fas fa-chart-line"></i></button>
                                                <button type="button" class="btn btn-outline-secondary"><i class="fas fa-cog"></i></button>
                                                <button type="button" class="btn btn-outline-danger"><i class="fas fa-pause"></i></button>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
                <!-- Server Monitoring -->
                <div class="card mb-4">
                    <div class="card-header bg-white d-flex justify-content-between align-items-center">
                        <h5 class="card-title mb-0">Server Monitoring</h5>
                        <span class="badge bg-success">All Servers Operational</span>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-hover table-striped mb-0">
                                <thead class="table-light">
                                    <tr>
                                        <th>Server</th>
                                        <th>IP Address</th>
                                        <th>Status</th>
                                        <th>CPU</th>
                                        <th>Memory</th>
                                        <th>Disk</th>
                                        <th>Last Check</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td>Web Server</td>
                                        <td>192.168.2.10</td>
                                        <td><span class="badge bg-success">Online</span></td>
                                        <td>15% <div class="progress" style="height: 5px;"><div class="progress-bar" role="progressbar" style="width: 15%"></div></div></td>
                                        <td>32% <div class="progress" style="height: 5px;"><div class="progress-bar" role="progressbar" style="width: 32%"></div></div></td>
                                        <td>45% <div class="progress" style="height: 5px;"><div class="progress-bar" role="progressbar" style="width: 45%"></div></div></td>
                                        <td>Just now</td>
                                        <td>
                                            <div class="btn-group btn-group-sm">
                                                <button type="button" class="btn btn-outline-primary"><i class="fas fa-chart-line"></i></button>
                                                <button type="button" class="btn btn-outline-secondary"><i class="fas fa-cog"></i></button>
                                                <button type="button" class="btn btn-outline-danger"><i class="fas fa-pause"></i></button>
                                            </div>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td>Database Server</td>
                                        <td>192.168.2.11</td>
                                        <td><span class="badge bg-success">Online</span></td>
                                        <td>25% <div class="progress" style="height: 5px;"><div class="progress-bar" role="progressbar" style="width: 25%"></div></div></td>
                                        <td>40% <div class="progress" style="height: 5px;"><div class="progress-bar" role="progressbar" style="width: 40%"></div></div></td>
                                        <td>35% <div class="progress" style="height: 5px;"><div class="progress-bar" role="progressbar" style="width: 35%"></div></div></td>
                                        <td>Just now</td>
                                        <td>
                                            <div class="btn-group btn-group-sm">
                                                <button type="button" class="btn btn-outline-primary"><i class="fas fa-chart-line"></i></button>
                                                <button type="button" class="btn btn-outline-secondary"><i class="fas fa-cog"></i></button>
                                                <button type="button" class="btn btn-outline-danger"><i class="fas fa-pause"></i></button>
                                            </div>
                                        </td>
                                    </tr>
                                    <tr>
                                       <tr>
                                        <td>Authentication Server</td>
                                        <td>192.168.2.12</td>
                                        <td><span class="badge bg-success">Online</span></td>
                                        <td>18% <div class="progress" style="height: 5px;"><div class="progress-bar" role="progressbar" style="width: 18%"></div></div></td>
                                        <td>35% <div class="progress" style="height: 5px;"><div class="progress-bar" role="progressbar" style="width: 35%"></div></div></td>
                                        <td>30% <div class="progress" style="height: 5px;"><div class="progress-bar" role="progressbar" style="width: 30%"></div></div></td>
                                        <td>Just now</td>
                                        <td>
                                            <div class="btn-group btn-group-sm">
                                                <button type="button" class="btn btn-outline-primary"><i class="fas fa-chart-line"></i></button>
                                                <button type="button" class="btn btn-outline-secondary"><i class="fas fa-cog"></i></button>
                                                <button type="button" class="btn btn-outline-danger"><i class="fas fa-pause"></i></button>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
                <!-- Service Monitoring -->
                <div class="card mb-4">
                    <div class="card-header bg-white d-flex justify-content-between align-items-center">
                        <h5 class="card-title mb-0">Service Monitoring</h5>
                        <span class="badge bg-success">All Services Operational</span>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-hover table-striped mb-0">
                                <thead class="table-light">
                                    <tr>
                                        <th>Service</th>
                                        <th>Host</th>
                                        <th>Status</th>
                                        <th>Response Time</th>
                                        <th>Uptime</th>
                                        <th>Last Check</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td>Web Application</td>
                                        <td>web.example.com</td>
                                        <td><span class="badge bg-success">Online</span></td>
                                        <td>235ms</td>
                                        <td>99.99%</td>
                                        <td>Just now</td>
                                        <td>
                                            <div class="btn-group btn-group-sm">
                                                <button type="button" class="btn btn-outline-primary"><i class="fas fa-chart-line"></i></button>
                                                <button type="button" class="btn btn-outline-secondary"><i class="fas fa-cog"></i></button>
                                                <button type="button" class="btn btn-outline-danger"><i class="fas fa-pause"></i></button>
                                            </div>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td>Email Service</td>
                                        <td>mail.example.com</td>
                                        <td><span class="badge bg-success">Online</span></td>
                                        <td>312ms</td>
                                        <td>99.95%</td>
                                        <td>Just now</td>
                                        <td>
                                            <div class="btn-group btn-group-sm">
                                                <button type="button" class="btn btn-outline-primary"><i class="fas fa-chart-line"></i></button>
                                                <button type="button" class="btn btn-outline-secondary"><i class="fas fa-cog"></i></button>
                                                <button type="button" class="btn btn-outline-danger"><i class="fas fa-pause"></i></button>
                                            </div>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td>VPN Service</td>
                                        <td>vpn.example.com</td>
                                        <td><span class="badge bg-success">Online</span></td>
                                        <td>189ms</td>
                                        <td>99.97%</td>
                                        <td>Just now</td>
                                        <td>
                                            <div class="btn-group btn-group-sm">
                                                <button type="button" class="btn btn-outline-primary"><i class="fas fa-chart-line"></i></button>
                                                <button type="button" class="btn btn-outline-secondary"><i class="fas fa-cog"></i></button>
                                                <button type="button" class="btn btn-outline-danger"><i class="fas fa-pause"></i></button>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
                <!-- Event Log -->
                <div class="card">
                    <div class="card-header bg-white d-flex justify-content-between align-items-center">
                        <h5 class="card-title mb-0">Monitoring Event Log</h5>
                        <button type="button" class="btn btn-sm btn-outline-secondary">Clear Log</button>
                    </div>
                    <div class="card-body p-0">
                        <div class="list-group list-group-flush" style="max-height: 300px; overflow-y: auto;">
                            <div class="list-group-item">
                                <div class="d-flex w-100 justify-content-between">
                                    <h6 class="mb-1">Monitoring service started</h6>
                                    <small>Just now</small>
                                </div>
                                <p class="mb-1 text-muted">All monitoring services initialized successfully.</p>
                            </div>
                            <div class="list-group-item">
                                <div class="d-flex w-100 justify-content-between">
                                    <h6 class="mb-1">Completed initial scan</h6>
                                    <small>Just now</small>
                                </div>
                                <p class="mb-1 text-muted">Initial scan of all monitored systems completed successfully.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>
    
    <!-- Monitoring Settings Modal -->
    <div class="modal fade" id="monitoringSettingsModal" tabindex="-1" aria-labelledby="monitoringSettingsModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="monitoringSettingsModalLabel">Monitoring Settings</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form method="post" action="#">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                        <input type="hidden" name="action" value="update_monitoring_settings">
                        
                        <div class="mb-3">
                            <label for="check_interval" class="form-label">Check Interval (seconds)</label>
                            <input type="number" class="form-control" id="check_interval" name="check_interval" value="60" min="30" required>
                            <div class="form-text">How often to check monitored systems and services.</div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="timeout" class="form-label">Connection Timeout (seconds)</label>
                            <input type="number" class="form-control" id="timeout" name="timeout" value="5" min="1" required>
                            <div class="form-text">Maximum time to wait for a response before marking as down.</div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="retry_attempts" class="form-label">Retry Attempts</label>
                            <input type="number" class="form-control" id="retry_attempts" name="retry_attempts" value="3" min="1" required>
                            <div class="form-text">Number of retry attempts before marking a service as down.</div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="retry_interval" class="form-label">Retry Interval (seconds)</label>
                            <input type="number" class="form-control" id="retry_interval" name="retry_interval" value="10" min="5" required>
                            <div class="form-text">Time to wait between retry attempts.</div>
                        </div>
                        
                        <div class="form-check form-switch mb-3">
                            <input class="form-check-input" type="checkbox" id="enable_notifications" name="enable_notifications" checked>
                            <label class="form-check-label" for="enable_notifications">Enable Notifications</label>
                        </div>
                        
                        <div class="form-check form-switch mb-3">
                            <input class="form-check-input" type="checkbox" id="auto_create_alerts" name="auto_create_alerts" checked>
                            <label class="form-check-label" for="auto_create_alerts">Automatically Create Alerts for Down Services</label>
                        </div>
                        
                        <div class="form-check form-switch mb-3">
                            <input class="form-check-input" type="checkbox" id="store_metrics" name="store_metrics" checked>
                            <label class="form-check-label" for="store_metrics">Store Historical Metrics</label>
                        </div>
                        
                        <div class="mb-3">
                            <label for="metrics_retention" class="form-label">Metrics Retention Period (days)</label>
                            <input type="number" class="form-control" id="metrics_retention" name="metrics_retention" value="30" min="1" required>
                            <div class="form-text">How long to retain historical metrics data.</div>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary">Save Settings</button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Include footer -->
    <?php include 'includes/footer.php'; ?>
    
    <!-- Include JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Auto-refresh the page periodically
        document.addEventListener('DOMContentLoaded', function() {
            // Refresh button handler
            document.getElementById('refreshBtn').addEventListener('click', function() {
                window.location.reload();
            });
            
            // Set up auto-refresh every 60 seconds
            const autoRefresh = setTimeout(function() {
                window.location.reload();
            }, 60000);
            
            // Clear auto-refresh if the user interacts with the page
            document.addEventListener('click', function() {
                clearTimeout(autoRefresh);
            });
        });
    </script>
</body>
</html>