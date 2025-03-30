<header class="navbar navbar-dark sticky-top bg-dark flex-md-nowrap p-0 shadow">
    <a class="navbar-brand col-md-3 col-lg-2 me-0 px-3" href="dashboard.php">
        <i class="fas fa-shield-alt"></i> <?php echo SITE_NAME; ?>
    </a>
    <button class="navbar-toggler position-absolute d-md-none collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#sidebarMenu" aria-controls="sidebarMenu" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
    </button>
    <input class="form-control form-control-dark w-100" type="text" placeholder="Search alerts, incidents, assets..." aria-label="Search">
    <div class="navbar-nav">
        <div class="nav-item dropdown">
            <a class="nav-link dropdown-toggle px-3" href="#" id="navbarDropdownAlerts" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                <i class="fas fa-bell"></i>
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
                <span class="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger">
                    <?php echo $newAlertsCount > 99 ? '99+' : $newAlertsCount; ?>
                    <span class="visually-hidden">new alerts</span>
                </span>
                <?php endif; ?>
            </a>
            <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="navbarDropdownAlerts">
                <li><h6 class="dropdown-header">Recent Alerts</h6></li>
                <?php
                // Get recent alerts
                $conn = connectDB();
                $query = "SELECT alert_id, alert_message, severity, created_at FROM alerts WHERE status = 'new' ORDER BY created_at DESC LIMIT 5";
                $result = $conn->query($query);
                
                if ($result->num_rows === 0):
                ?>
                <li><span class="dropdown-item-text text-muted">No new alerts</span></li>
                <?php else:
                    while ($alert = $result->fetch_assoc()):
                ?>
                <li>
                    <a class="dropdown-item" href="alert-details.php?id=<?php echo $alert['alert_id']; ?>">
                        <div class="d-flex align-items-center">
                            <div class="me-2">
                                <?php
                                $iconClass = 'text-info';
                                switch ($alert['severity']) {
                                    case 'critical':
                                        $iconClass = 'text-danger';
                                        break;
                                    case 'high':
                                        $iconClass = 'text-warning';
                                        break;
                                    case 'medium':
                                        $iconClass = 'text-primary';
                                        break;
                                    case 'low':
                                        $iconClass = 'text-success';
                                        break;
                                }
                                ?>
                                <i class="fas fa-exclamation-circle <?php echo $iconClass; ?>"></i>
                            </div>
                            <div>
                                <div class="small text-truncate" style="max-width: 200px;"><?php echo htmlspecialchars($alert['alert_message']); ?></div>
                                <div class="text-muted small"><?php echo date('M d, H:i', strtotime($alert['created_at'])); ?></div>
                            </div>
                        </div>
                    </a>
                </li>
                <?php
                    endwhile;
                endif;
                $conn->close();
                ?>
                <li><hr class="dropdown-divider"></li>
                <li><a class="dropdown-item text-center" href="alerts.php">View all alerts</a></li>
            </ul>
        </div>
        <div class="nav-item dropdown">
            <a class="nav-link dropdown-toggle px-3" href="#" id="navbarDropdownUser" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                <i class="fas fa-user-circle"></i> <?php echo htmlspecialchars($_SESSION['username']); ?>
            </a>
            <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="navbarDropdownUser">
                <li><a class="dropdown-item" href="profile.php"><i class="fas fa-user me-2"></i> Profile</a></li>
                <li><a class="dropdown-item" href="settings.php"><i class="fas fa-cog me-2"></i> Settings</a></li>
                <li><a class="dropdown-item" href="activity-log.php"><i class="fas fa-list me-2"></i> Activity Log</a></li>
                <li><hr class="dropdown-divider"></li>
                <li><a class="dropdown-item" href="logout.php"><i class="fas fa-sign-out-alt me-2"></i> Logout</a></li>
            </ul>
        </div>
    </div>
</header>