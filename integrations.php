<?php
require_once 'config.php';

// Initialize secure session
initSecureSession();

// Check if user is authenticated, redirect to login if not
if (!isAuthenticated()) {
    header("Location: index.php");
    exit;
}

// Check if user has admin or manager role
if (!hasRole('admin', 'manager')) {
    $_SESSION['error_message'] = "You don't have permission to access this page.";
    header("Location: dashboard.php");
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
    <title>Integrations - <?php echo SITE_NAME; ?></title>
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
                        <li class="breadcrumb-item active" aria-current="page">Integrations</li>
                    </ol>
                </nav>
                
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2"><i class="fas fa-plug"></i> Integrations</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#addIntegrationModal">
                            <i class="fas fa-plus"></i> Add Integration
                        </button>
                    </div>
                </div>
                
                <!-- Integrations Categories -->
                <div class="row mb-4">
                    <div class="col-md-4 mb-3">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title"><i class="fas fa-shield-alt me-2"></i>Security Tools</h5>
                                <p class="card-text">Connect with firewalls, IDS/IPS, EDRs, and other security tools.</p>
                                <a href="#security-tools" class="btn btn-outline-primary" data-bs-toggle="collapse" role="button" aria-expanded="false">
                                    View Integrations
                                </a>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-4 mb-3">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title"><i class="fas fa-ticket-alt me-2"></i>Ticketing Systems</h5>
                                <p class="card-text">Connect with ITSM platforms and ticketing systems.</p>
                                <a href="#ticketing-systems" class="btn btn-outline-primary" data-bs-toggle="collapse" role="button" aria-expanded="false">
                                    View Integrations
                                </a>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-4 mb-3">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title"><i class="fas fa-comment-alt me-2"></i>Communication</h5>
                                <p class="card-text">Connect with communication and notification platforms.</p>
                                <a href="#communication" class="btn btn-outline-primary" data-bs-toggle="collapse" role="button" aria-expanded="false">
                                    View Integrations
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Security Tools Section -->
                <div class="collapse mb-4" id="security-tools">
                    <div class="card">
                        <div class="card-header bg-white">
                            <h5 class="card-title mb-0">Security Tools</h5>
                        </div>
                        <div class="card-body p-0">
                            <div class="list-group list-group-flush">
                                <div class="list-group-item d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="mb-1">SIEM Integration</h6>
                                        <p class="mb-0 text-muted small">Connect to your SIEM platform to import alerts</p>
                                    </div>
                                    <span class="badge bg-secondary">Not Configured</span>
                                </div>
                                
                                <div class="list-group-item d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="mb-1">Firewall Integration</h6>
                                        <p class="mb-0 text-muted small">Connect to firewalls to import events and manage rules</p>
                                    </div>
                                    <span class="badge bg-secondary">Not Configured</span>
                                </div>
                                
                                <div class="list-group-item d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="mb-1">EDR Integration</h6>
                                        <p class="mb-0 text-muted small">Connect to EDR systems to manage endpoints</p>
                                    </div>
                                    <span class="badge bg-secondary">Not Configured</span>
                                </div>
                                
                                <div class="list-group-item d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="mb-1">Vulnerability Scanner</h6>
                                        <p class="mb-0 text-muted small">Import vulnerability data from scanners</p>
                                    </div>
                                    <span class="badge bg-secondary">Not Configured</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Ticketing Systems Section -->
                <div class="collapse mb-4" id="ticketing-systems">
                    <div class="card">
                        <div class="card-header bg-white">
                            <h5 class="card-title mb-0">Ticketing Systems</h5>
                        </div>
                        <div class="card-body p-0">
                            <div class="list-group list-group-flush">
                                <div class="list-group-item d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="mb-1">JIRA Integration</h6>
                                        <p class="mb-0 text-muted small">Create and track issues in JIRA</p>
                                    </div>
                                    <span class="badge bg-secondary">Not Configured</span>
                                </div>
                                
                                <div class="list-group-item d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="mb-1">ServiceNow Integration</h6>
                                        <p class="mb-0 text-muted small">Create and track tickets in ServiceNow</p>
                                    </div>
                                    <span class="badge bg-secondary">Not Configured</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Communication Section -->
                <div class="collapse mb-4" id="communication">
                    <div class="card">
                        <div class="card-header bg-white">
                            <h5 class="card-title mb-0">Communication</h5>
                        </div>
                        <div class="card-body p-0">
                            <div class="list-group list-group-flush">
                                <div class="list-group-item d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="mb-1">Slack Integration</h6>
                                        <p class="mb-0 text-muted small">Send notifications to Slack channels</p>
                                    </div>
                                    <span class="badge bg-secondary">Not Configured</span>
                                </div>
                                
                                <div class="list-group-item d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="mb-1">Microsoft Teams Integration</h6>
                                        <p class="mb-0 text-muted small">Send notifications to Microsoft Teams</p>
                                    </div>
                                    <span class="badge bg-secondary">Not Configured</span>
                                </div>
                                
                                <div class="list-group-item d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="mb-1">SMS Notification</h6>
                                        <p class="mb-0 text-muted small">Send SMS alerts for critical events</p>
                                    </div>
                                    <span class="badge bg-secondary">Not Configured</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- API Documentation -->
                <div class="card mb-4">
                    <div class="card-header bg-white">
                        <h5 class="card-title mb-0">API Documentation</h5>
                    </div>
                    <div class="card-body">
                        <p>Use our API to integrate with custom systems or third-party tools.</p>
                        <p>The SOC system provides RESTful APIs for accessing and managing security alerts, incidents, and more.</p>
                        <a href="#" class="btn btn-outline-primary">View API Documentation</a>
                    </div>
                </div>
            </main>
        </div>
    </div>
    
    <!-- Add Integration Modal -->
    <div class="modal fade" id="addIntegrationModal" tabindex="-1" aria-labelledby="addIntegrationModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="addIntegrationModalLabel">Add New Integration</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i> Select an integration type to configure.
                    </div>
                    
                    <form method="post" action="#">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                        <input type="hidden" name="action" value="add_integration">
                        
                        <div class="mb-3">
                            <label for="integration_type" class="form-label">Integration Type</label>
                            <select class="form-select" id="integration_type" name="integration_type" required>
                                <option value="">-- Select Integration Type --</option>
                                <optgroup label="Security Tools">
                                    <option value="siem">SIEM Platform</option>
                                    <option value="firewall">Firewall</option>
                                    <option value="edr">EDR System</option>
                                    <option value="vulnerability_scanner">Vulnerability Scanner</option>
                                </optgroup>
                                <optgroup label="Ticketing Systems">
                                    <option value="jira">JIRA</option>
                                    <option value="servicenow">ServiceNow</option>
                                </optgroup>
                                <optgroup label="Communication">
                                    <option value="slack">Slack</option>
                                    <option value="teams">Microsoft Teams</option>
                                    <option value="sms">SMS Notification</option>
                                </optgroup>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <label for="integration_name" class="form-label">Integration Name</label>
                            <input type="text" class="form-control" id="integration_name" name="integration_name" placeholder="e.g., Production Firewall" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="api_url" class="form-label">API URL</label>
                            <input type="url" class="form-control" id="api_url" name="api_url" placeholder="https://api.example.com" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="api_key" class="form-label">API Key / Token</label>
                            <input type="password" class="form-control" id="api_key" name="api_key" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="auth_type" class="form-label">Authentication Type</label>
                            <select class="form-select" id="auth_type" name="auth_type">
                                <option value="api_key">API Key</option>
                                <option value="oauth2">OAuth 2.0</option>
                                <option value="basic_auth">Basic Auth</option>
                            </select>
                        </div>
                        
                        <div class="form-check form-switch mb-3">
                            <input class="form-check-input" type="checkbox" id="is_active" name="is_active" checked>
                            <label class="form-check-label" for="is_active">Active</label>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary">Add Integration</button>
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