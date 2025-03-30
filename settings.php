<?php
require_once 'config.php';

// Initialize secure session
initSecureSession();

// Check if user is authenticated, redirect to login if not
if (!isAuthenticated()) {
    header("Location: index.php");
    exit;
}

// Check if user has admin role
if (!hasRole('admin')) {
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
    <title>System Settings - <?php echo SITE_NAME; ?></title>
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
                        <li class="breadcrumb-item active" aria-current="page">System Settings</li>
                    </ol>
                </nav>
                
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2"><i class="fas fa-sliders-h"></i> System Settings</h1>
                </div>
                
                <!-- Settings Tabs -->
                <div class="card">
                    <div class="card-header bg-white">
                        <ul class="nav nav-tabs card-header-tabs" role="tablist">
                            <li class="nav-item" role="presentation">
                                <button class="nav-link active" id="general-tab" data-bs-toggle="tab" data-bs-target="#general" type="button" role="tab" aria-controls="general" aria-selected="true">General</button>
                            </li>
                            <li class="nav-item" role="presentation">
                                <button class="nav-link" id="email-tab" data-bs-toggle="tab" data-bs-target="#email" type="button" role="tab" aria-controls="email" aria-selected="false">Email</button>
                            </li>
                            <li class="nav-item" role="presentation">
                                <button class="nav-link" id="security-tab" data-bs-toggle="tab" data-bs-target="#security" type="button" role="tab" aria-controls="security" aria-selected="false">Security</button>
                            </li>
                            <li class="nav-item" role="presentation">
                                <button class="nav-link" id="backup-tab" data-bs-toggle="tab" data-bs-target="#backup" type="button" role="tab" aria-controls="backup" aria-selected="false">Backup</button>
                            </li>
                        </ul>
                    </div>
                    <div class="card-body">
                        <div class="tab-content">
                            <!-- General Settings -->
                            <div class="tab-pane fade show active" id="general" role="tabpanel" aria-labelledby="general-tab">
                                <form method="post" action="#">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                                    <input type="hidden" name="action" value="update_general">
                                    
                                    <div class="mb-3">
                                        <label for="site_name" class="form-label">Site Name</label>
                                        <input type="text" class="form-control" id="site_name" name="site_name" value="<?php echo SITE_NAME; ?>">
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="timezone" class="form-label">Timezone</label>
                                        <select class="form-select" id="timezone" name="timezone">
                                            <option value="UTC">UTC</option>
                                            <option value="America/New_York">Eastern Time (US & Canada)</option>
                                            <option value="America/Chicago">Central Time (US & Canada)</option>
                                            <option value="America/Denver">Mountain Time (US & Canada)</option>
                                            <option value="America/Los_Angeles">Pacific Time (US & Canada)</option>
                                            <option value="Europe/London">London</option>
                                            <option value="Europe/Paris">Paris</option>
                                            <option value="Asia/Tokyo">Tokyo</option>
                                            <option value="Asia/Shanghai">Shanghai</option>
                                            <option value="Asia/Kolkata">New Delhi</option>
                                        </select>
                                    </div>
                                    
                                    <div class="form-check form-switch mb-3">
                                        <input class="form-check-input" type="checkbox" id="dark_mode" name="dark_mode">
                                        <label class="form-check-label" for="dark_mode">Default to Dark Mode</label>
                                    </div>
                                    
                                    <button type="submit" class="btn btn-primary">Save Changes</button>
                                </form>
                            </div>
                            
                            <!-- Email Settings -->
                            <div class="tab-pane fade" id="email" role="tabpanel" aria-labelledby="email-tab">
                                <form method="post" action="#">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                                    <input type="hidden" name="action" value="update_email">
                                    
                                    <div class="mb-3">
                                        <label for="smtp_host" class="form-label">SMTP Host</label>
                                        <input type="text" class="form-control" id="smtp_host" name="smtp_host">
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="smtp_port" class="form-label">SMTP Port</label>
                                        <input type="text" class="form-control" id="smtp_port" name="smtp_port" value="587">
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="smtp_username" class="form-label">SMTP Username</label>
                                        <input type="text" class="form-control" id="smtp_username" name="smtp_username">
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="smtp_password" class="form-label">SMTP Password</label>
                                        <input type="password" class="form-control" id="smtp_password" name="smtp_password">
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="smtp_from_email" class="form-label">From Email</label>
                                        <input type="email" class="form-control" id="smtp_from_email" name="smtp_from_email">
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="smtp_from_name" class="form-label">From Name</label>
                                        <input type="text" class="form-control" id="smtp_from_name" name="smtp_from_name">
                                    </div>
                                    
                                    <div class="form-check form-switch mb-3">
                                        <input class="form-check-input" type="checkbox" id="smtp_tls" name="smtp_tls" checked>
                                        <label class="form-check-label" for="smtp_tls">Use TLS</label>
                                    </div>
                                    
                                    <button type="submit" class="btn btn-primary">Save Email Settings</button>
                                </form>
                            </div>
                            
                            <!-- Security Settings -->
                            <div class="tab-pane fade" id="security" role="tabpanel" aria-labelledby="security-tab">
                                <form method="post" action="#">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                                    <input type="hidden" name="action" value="update_security">
                                    
                                    <div class="mb-3">
                                        <label for="session_lifetime" class="form-label">Session Lifetime (seconds)</label>
                                        <input type="number" class="form-control" id="session_lifetime" name="session_lifetime" value="3600">
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="password_min_length" class="form-label">Minimum Password Length</label>
                                        <input type="number" class="form-control" id="password_min_length" name="password_min_length" value="12">
                                    </div>
                                    
                                    <div class="form-check form-switch mb-3">
                                        <input class="form-check-input" type="checkbox" id="password_requires_special" name="password_requires_special" checked>
                                        <label class="form-check-label" for="password_requires_special">Require Special Characters</label>
                                    </div>
                                    
                                    <div class="form-check form-switch mb-3">
                                        <input class="form-check-input" type="checkbox" id="password_requires_number" name="password_requires_number" checked>
                                        <label class="form-check-label" for="password_requires_number">Require Numbers</label>
                                    </div>
                                    
                                    <div class="form-check form-switch mb-3">
                                        <input class="form-check-input" type="checkbox" id="password_requires_uppercase" name="password_requires_uppercase" checked>
                                        <label class="form-check-label" for="password_requires_uppercase">Require Uppercase Letters</label>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="account_lockout_threshold" class="form-label">Account Lockout Threshold</label>
                                        <input type="number" class="form-control" id="account_lockout_threshold" name="account_lockout_threshold" value="5">
                                        <div class="form-text">Number of failed login attempts before lockout</div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="account_lockout_duration" class="form-label">Account Lockout Duration (seconds)</label>
                                        <input type="number" class="form-control" id="account_lockout_duration" name="account_lockout_duration" value="1800">
                                    </div>
                                    
                                    <button type="submit" class="btn btn-primary">Save Security Settings</button>
                                </form>
                            </div>
                            
                            <!-- Backup Settings -->
                            <div class="tab-pane fade" id="backup" role="tabpanel" aria-labelledby="backup-tab">
                                <div class="alert alert-info">
                                    <i class="fas fa-info-circle"></i> Configure automated backups for your SOC system data.
                                </div>
                                
                                <form method="post" action="#">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                                    <input type="hidden" name="action" value="update_backup">
                                    
                                    <div class="form-check form-switch mb-3">
                                        <input class="form-check-input" type="checkbox" id="enable_backups" name="enable_backups">
                                        <label class="form-check-label" for="enable_backups">Enable Automated Backups</label>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="backup_frequency" class="form-label">Backup Frequency</label>
                                        <select class="form-select" id="backup_frequency" name="backup_frequency">
                                            <option value="daily">Daily</option>
                                            <option value="weekly">Weekly</option>
                                            <option value="monthly">Monthly</option>
                                        </select>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="backup_retention" class="form-label">Backup Retention (days)</label>
                                        <input type="number" class="form-control" id="backup_retention" name="backup_retention" value="30">
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="backup_path" class="form-label">Backup Path</label>
                                        <input type="text" class="form-control" id="backup_path" name="backup_path" value="/backups">
                                    </div>
                                    
                                    <button type="submit" class="btn btn-primary">Save Backup Settings</button>
                                </form>
                                
                                <hr>
                                
                                <h5>Manual Backup</h5>
                                <p>Create an immediate backup of your SOC system data.</p>
                                <button type="button" class="btn btn-outline-primary">Create Backup Now</button>
                                
                                <h5 class="mt-4">Backup History</h5>
                                <p class="text-muted">No backup history available.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>
    
    <!-- Include footer -->
    <?php include 'includes/footer.php'; ?>
    
    <!-- Include JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>