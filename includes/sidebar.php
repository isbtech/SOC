<nav id="sidebarMenu" class="col-md-3 col-lg-2 d-md-block bg-light sidebar collapse">
    <div class="position-sticky pt-3">
        <ul class="nav flex-column">
            <li class="nav-item">
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'assets.php' ? 'active' : ''; ?>" href="assets.php">
                    <i class="fas fa-laptop me-2"></i>
                    Assets
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'vulnerabilities.php' ? 'active' : ''; ?>" href="vulnerabilities.php">
                    <i class="fas fa-bug me-2"></i>
                    Vulnerabilities
                    <?php
                    // Get count of critical vulnerabilities
                    $conn = connectDB();
                    $query = "SELECT COUNT(*) as count FROM vulnerabilities WHERE severity = 'critical' AND status = 'open'";
                    $result = $conn->query($query);
                    $row = $result->fetch_assoc();
                    $criticalVulnCount = $row['count'];
                    $conn->close();
                    
                    if ($criticalVulnCount > 0):
                    ?>
                    <span class="badge rounded-pill bg-danger ms-2"><?php echo $criticalVulnCount; ?></span>
                    <?php endif; ?>
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'reports.php' ? 'active' : ''; ?>" href="reports.php">
                    <i class="fas fa-chart-bar me-2"></i>
                    Reports
                </a>
            </li>
            
            <li class="nav-item">
                <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'monitoring.php' ? 'active' : ''; ?>" href="monitoring.php">
                    <i class="fas fa-desktop me-2"></i>
                    Monitoring
                </a>
            </li>
        </ul>

        <h6 class="sidebar-heading d-flex justify-content-between align-items-center px-3 mt-4 mb-1 text-muted">
            <span>Configuration</span>
        </h6>
        <ul class="nav flex-column mb-2">
            <li class="nav-item">
                <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'alert-rules.php' ? 'active' : ''; ?>" href="alert-rules.php">
                    <i class="fas fa-cogs me-2"></i>
                    Alert Rules
                </a>
            </li>
            <?php if (hasRole('admin') || hasRole('manager')): ?>
            <li class="nav-item">
                <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'users.php' ? 'active' : ''; ?>" href="users.php">
                    <i class="fas fa-users me-2"></i>
                    Users
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'integrations.php' ? 'active' : ''; ?>" href="integrations.php">
                    <i class="fas fa-plug me-2"></i>
                    Integrations
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'settings.php' ? 'active' : ''; ?>" href="settings.php">
                    <i class="fas fa-sliders-h me-2"></i>
                    System Settings
                </a>
            </li>
            <?php endif; ?>
        </ul>
        
        <h6 class="sidebar-heading d-flex justify-content-between align-items-center px-3 mt-4 mb-1 text-muted">
            <span>Resources</span>
        </h6>
        <ul class="nav flex-column mb-2">
            <li class="nav-item">
                <a class="nav-link" href="playbooks.php">
                    <i class="fas fa-book me-2"></i>
                    Playbooks
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="knowledge-base.php">
                    <i class="fas fa-lightbulb me-2"></i>
                    Knowledge Base
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="documentation.php">
                    <i class="fas fa-file-alt me-2"></i>
                    Documentation
                </a>
            </li>
        </ul>
    </div>
</nav><a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'dashboard.php' ? 'active' : ''; ?>" href="dashboard.php">
                    <i class="fas fa-tachometer-alt me-2"></i>
                    Dashboard
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'alerts.php' ? 'active' : ''; ?>" href="alerts.php">
                    <i class="fas fa-bell me-2"></i>
                    Alerts
                    <?php
                    // Get count of new alerts
                    $conn = connectDB();
                    $query = "SELECT COUNT(*) as count FROM alerts WHERE status = 'new'";
                    $result = $conn->query($query);
                    $row = $result->fetch_assoc();
                    $newAlertsCount = $row['count'];
                    $conn->close();
                    
                    if ($newAlertsCount > 0):
                    ?>
                    <span class="badge rounded-pill bg-danger ms-2"><?php echo $newAlertsCount; ?></span>
                    <?php endif; ?>
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'incidents.php' ? 'active' : ''; ?>" href="incidents.php">
                    <i class="fas fa-file-alt me-2"></i>
                    Incidents
                    <?php
                    // Get count of open incidents
                    $conn = connectDB();
                    $query = "SELECT COUNT(*) as count FROM incidents WHERE status != 'closed'";
                    $result = $conn->query($query);
                    $row = $result->fetch_assoc();
                    $openIncidentsCount = $row['count'];
                    $conn->close();
                    
                    if ($openIncidentsCount > 0):
                    ?>
                    <span class="badge rounded-pill bg-primary ms-2"><?php echo $openIncidentsCount; ?></span>
                    <?php endif; ?>
                