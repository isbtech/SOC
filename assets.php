                $message = "Invalid MAC address format";
                $messageType = "danger";
            } else {
                // Insert new asset
                $stmt = $conn->prepare("INSERT INTO assets (asset_name, asset_type, ip_address, mac_address, location, department, owner, criticality, description, added_by, created_at) 
                                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())");
                $stmt->bind_param("sssssssssi", $assetName, $assetType, $ipAddress, $macAddress, $location, $department, $owner, $criticality, $description, $userId);
                
                if ($stmt->execute()) {
                    $message = "Asset added successfully";
                    $messageType = "success";
                    
                    // Log the action
                    logSecurityEvent('asset', 'info', "Added new asset: $assetName", $userId, getClientIP());
                } else {
                    $message = "Error adding asset: " . $conn->error;
                    $messageType = "danger";
                }
                $stmt->close();
            }
        }
        
        // Delete asset
        else if ($action === 'delete_asset' && hasRole('admin', 'manager')) {
            $assetId = intval($_POST['asset_id']);
            
            // Get asset name for logging
            $stmt = $conn->prepare("SELECT asset_name FROM assets WHERE asset_id = ?");
            $stmt->bind_param("i", $assetId);
            $stmt->execute();
            $result = $stmt->get_result();
            $assetName = "";
            if ($row = $result->fetch_assoc()) {
                $assetName = $row['asset_name'];
            }
            $stmt->close();
            
            // Delete the asset
            $stmt = $conn->prepare("DELETE FROM assets WHERE asset_id = ?");
            $stmt->bind_param("i", $assetId);
            
            if ($stmt->execute()) {
                $message = "Asset deleted successfully";
                $messageType = "success";
                
                // Log the action
                logSecurityEvent('asset', 'warning', "Deleted asset ID: $assetId, Name: $assetName", $userId, getClientIP());
            } else {
                $message = "Error deleting asset: " . $conn->error;
                $messageType = "danger";
            }
            $stmt->close();
        }
        
        // Update asset
        else if ($action === 'update_asset' && hasRole('admin', 'manager', 'analyst')) {
            $assetId = intval($_POST['asset_id']);
            $assetName = sanitizeInput($_POST['asset_name']);
            $assetType = sanitizeInput($_POST['asset_type']);
            $ipAddress = sanitizeInput($_POST['ip_address']);
            $macAddress = sanitizeInput($_POST['mac_address']);
            $location = sanitizeInput($_POST['location']);
            $department = sanitizeInput($_POST['department']);
            $owner = sanitizeInput($_POST['owner']);
            $criticality = sanitizeInput($_POST['criticality']);
            $description = sanitizeInput($_POST['description']);
            
            // Validate IP address if provided
            if (!empty($ipAddress) && !filter_var($ipAddress, FILTER_VALIDATE_IP)) {
                $message = "Invalid IP address format";
                $messageType = "danger";
            } 
            // Validate MAC address if provided
            else if (!empty($macAddress) && !preg_match('/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/', $macAddress)) {
                $message = "Invalid MAC address format";
                $messageType = "danger";
            } else {
                // Update asset
                $stmt = $conn->prepare("UPDATE assets SET asset_name = ?, asset_type = ?, ip_address = ?, mac_address = ?, 
                                       location = ?, department = ?, owner = ?, criticality = ?, description = ?, 
                                       updated_at = NOW() WHERE asset_id = ?");
                $stmt->bind_param("sssssssssi", $assetName, $assetType, $ipAddress, $macAddress, $location, $department, 
                                 $owner, $criticality, $description, $assetId);
                
                if ($stmt->execute()) {
                    $message = "Asset updated successfully";
                    $messageType = "success";
                    
                    // Log the action
                    logSecurityEvent('asset', 'info', "Updated asset: $assetName, ID: $assetId", $userId, getClientIP());
                } else {
                    $message = "Error updating asset: " . $conn->error;
                    $messageType = "danger";
                }
                $stmt->close();
            }
        }
    }
}

// Pagination parameters
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$limit = isset($_GET['limit']) ? intval($_GET['limit']) : 25;
$offset = ($page - 1) * $limit;

// Filtering parameters
$filterType = isset($_GET['asset_type']) ? $_GET['asset_type'] : '';
$filterCriticality = isset($_GET['criticality']) ? $_GET['criticality'] : '';
$filterLocation = isset($_GET['location']) ? $_GET['location'] : '';
$filterDepartment = isset($_GET['department']) ? $_GET['department'] : '';
$searchQuery = isset($_GET['search']) ? $_GET['search'] : '';

// Build the query
$query = "SELECT * FROM assets WHERE 1=1";
$countQuery = "SELECT COUNT(*) as total FROM assets WHERE 1=1";

$params = [];
$types = "";

// Add filters to the query
if (!empty($filterType)) {
    $query .= " AND asset_type = ?";
    $countQuery .= " AND asset_type = ?";
    $params[] = $filterType;
    $types .= "s";
}

if (!empty($filterCriticality)) {
    $query .= " AND criticality = ?";
    $countQuery .= " AND criticality = ?";
    $params[] = $filterCriticality;
    $types .= "s";
}

if (!empty($filterLocation)) {
    $query .= " AND location = ?";
    $countQuery .= " AND location = ?";
    $params[] = $filterLocation;
    $types .= "s";
}

if (!empty($filterDepartment)) {
    $query .= " AND department = ?";
    $countQuery .= " AND department = ?";
    $params[] = $filterDepartment;
    $types .= "s";
}

if (!empty($searchQuery)) {
    $query .= " AND (asset_name LIKE ? OR ip_address LIKE ? OR mac_address LIKE ? OR owner LIKE ? OR description LIKE ?)";
    $countQuery .= " AND (asset_name LIKE ? OR ip_address LIKE ? OR mac_address LIKE ? OR owner LIKE ? OR description LIKE ?)";
    $searchParam = "%" . $searchQuery . "%";
    $params[] = $searchParam;
    $params[] = $searchParam;
    $params[] = $searchParam;
    $params[] = $searchParam;
    $params[] = $searchParam;
    $types .= "sssss";
}

// Add sorting and pagination
$query .= " ORDER BY asset_name ASC LIMIT ? OFFSET ?";
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

// Get assets
$stmt = $conn->prepare($query);
if (!empty($types)) {
    $stmt->bind_param($types, ...$params);
}
$stmt->execute();
$result = $stmt->get_result();
$assets = [];
while ($row = $result->fetch_assoc()) {
    $assets[] = $row;
}

// Get asset types for filter
$assetTypes = [];
$query = "SELECT asset_type, COUNT(*) as count FROM assets GROUP BY asset_type ORDER BY asset_type";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $assetTypes[$row['asset_type']] = $row['count'];
}

// Get locations for filter
$locations = [];
$query = "SELECT location, COUNT(*) as count FROM assets WHERE location != '' GROUP BY location ORDER BY location";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $locations[$row['location']] = $row['count'];
}

// Get departments for filter
$departments = [];
$query = "SELECT department, COUNT(*) as count FROM assets WHERE department != '' GROUP BY department ORDER BY department";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $departments[$row['department']] = $row['count'];
}

// Get criticality counts for display
$criticalityCounts = [];
$query = "SELECT criticality, COUNT(*) as count FROM assets GROUP BY criticality ORDER BY 
         FIELD(criticality, 'critical', 'high', 'medium', 'low')";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $criticalityCounts[$row['criticality']] = $row['count'];
}

// Get vulnerability counts per asset
$assetVulnerabilities = [];
$query = "SELECT asset_id, COUNT(*) as count FROM vulnerabilities WHERE status = 'open' GROUP BY asset_id";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $assetVulnerabilities[$row['asset_id']] = $row['count'];
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
    <title>Asset Inventory - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="assets/css/style.css">
    <!-- Include modern UI framework CSS (Bootstrap, etc.) -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Include Font Awesome for icons -->
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
                        <li class="breadcrumb-item active" aria-current="page">Asset Inventory</li>
                    </ol>
                </nav>

                <?php if (isset($message)): ?>
                    <div class="alert alert-<?php echo $messageType; ?> alert-dismissible fade show" role="alert">
                        <?php echo $message; ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                <?php endif; ?>
                
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2"><i class="fas fa-laptop"></i> Asset Inventory</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <div class="btn-group me-2">
                            <button type="button" class="btn btn-sm btn-outline-secondary" id="refreshBtn">
                                <i class="fas fa-sync-alt"></i> Refresh
                            </button>
                            <button type="button" class="btn btn-sm btn-outline-secondary" data-bs-toggle="modal" data-bs-target="#exportModal">
                                <i class="fas fa-download"></i> Export
                            </button>
                        </div>
                        <?php if (hasRole('admin', 'manager', 'analyst')): ?>
                        <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#addAssetModal">
                            <i class="fas fa-plus"></i> Add Asset
                        </button>
                        <?php endif; ?>
                    </div>
                </div>
                
                <!-- Asset Stats -->
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="card bg-danger text-white h-100">
                            <div class="card-body py-3">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="card-title mb-0">Critical Assets</h6>
                                        <h2 class="mt-2 mb-0"><?php echo isset($criticalityCounts['critical']) ? $criticalityCounts['critical'] : 0; ?></h2>
                                    </div>
                                    <i class="fas fa-server fa-2x"></i>
                                </div>
                            </div>
                            <div class="card-footer d-flex align-items-center justify-content-between">
                                <a href="?criticality=critical" class="text-white text-decoration-none small">View details</a>
                                <i class="fas fa-arrow-circle-right text-white"></i>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-3">
                        <div class="card bg-warning text-dark h-100">
                            <div class="card-body py-3">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="card-title mb-0">High Priority Assets</h6>
                                        <h2 class="mt-2 mb-0"><?php echo isset($criticalityCounts['high']) ? $criticalityCounts['high'] : 0; ?></h2>
                                    </div>
                                    <i class="fas fa-database fa-2x"></i>
                                </div>
                            </div>
                            <div class="card-footer d-flex align-items-center justify-content-between">
                                <a href="?criticality=high" class="text-dark text-decoration-none small">View details</a>
                                <i class="fas fa-arrow-circle-right text-dark"></i>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-3">
                        <div class="card bg-primary text-white h-100">
                            <div class="card-body py-3">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="card-title mb-0">Total Assets</h6>
                                        <h2 class="mt-2 mb-0"><?php echo $totalRows; ?></h2>
                                    </div>
                                    <i class="fas fa-laptop fa-2x"></i>
                                </div>
                            </div>
                            <div class="card-footer d-flex align-items-center justify-content-between">
                                <a href="assets.php" class="text-white text-decoration-none small">View all</a>
                                <i class="fas fa-arrow-circle-right text-white"></i>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-3">
                        <div class="card bg-success text-white h-100">
                            <div class="card-body py-3">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="card-title mb-0">Asset Types</h6>
                                        <h2 class="mt-2 mb-0"><?php echo count($assetTypes); ?></h2>
                                    </div>
                                    <i class="fas fa-network-wired fa-2x"></i>
                                </div>
                            </div>
                            <div class="card-footer d-flex align-items-center justify-content-between">
                                <span class="text-white text-decoration-none small">Different categories</span>
                                <i class="fas fa-arrow-circle-right text-white"></i>
                            </div>
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
                            <form action="assets.php" method="get" id="filterForm">
                                <div class="row g-3">
                                    <div class="col-md-3">
                                        <label for="asset_type" class="form-label">Asset Type</label>
                                        <select class="form-select" id="asset_type" name="asset_type">
                                            <option value="">All Types</option>
                                            <?php foreach ($assetTypes as $type => $count): ?>
                                                <option value="<?php echo $type; ?>" <?php echo $filterType === $type ? 'selected' : ''; ?>>
                                                    <?php echo ucfirst(str_replace('_', ' ', $type)); ?> (<?php echo $count; ?>)
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                    <div class="col-md-3">
                                        <label for="criticality" class="form-label">Criticality</label>
                                        <select class="form-select" id="criticality" name="criticality">
                                            <option value="">All Criticalities</option>
                                            <option value="critical" <?php echo $filterCriticality === 'critical' ? 'selected' : ''; ?>>
                                                Critical
                                            </option>
                                            <option value="high" <?php echo $filterCriticality === 'high' ? 'selected' : ''; ?>>
                                                High
                                            </option>
                                            <option value="medium" <?php echo $filterCriticality === 'medium' ? 'selected' : ''; ?>>
                                                Medium
                                            </option>
                                            <option value="low" <?php echo $filterCriticality === 'low' ? 'selected' : ''; ?>>
                                                Low
                                            </option>
                                        </select>
                                    </div>
                                    <div class="col-md-3">
                                        <label for="location" class="form-label">Location</label>
                                        <select class="form-select" id="location" name="location">
                                            <option value="">All Locations</option>
                                            <?php foreach ($locations as $loc => $count): ?>
                                                <option value="<?php echo $loc; ?>" <?php echo $filterLocation === $loc ? 'selected' : ''; ?>>
                                                    <?php echo htmlspecialchars($loc); ?> (<?php echo $count; ?>)
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                    <div class="col-md-3">
                                        <label for="department" class="form-label">Department</label>
                                        <select class="form-select" id="department" name="department">
                                            <option value="">All Departments</option>
                                            <?php foreach ($departments as $dept => $count): ?>
                                                <option value="<?php echo $dept; ?>" <?php echo $filterDepartment === $dept ? 'selected' : ''; ?>>
                                                    <?php echo htmlspecialchars($dept); ?> (<?php echo $count; ?>)
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label for="search" class="form-label">Search</label>
                                        <input type="text" class="form-control" id="search" name="search" placeholder="Search by name, IP, MAC, owner..." value="<?php echo htmlspecialchars($searchQuery); ?>">
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
                                        <a href="assets.php" class="btn btn-outline-secondary">
                                            <i class="fas fa-undo"></i> Clear Filters
                                        </a>
                                    </div>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
                
                <!-- Assets table -->
                <div class="card">
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-hover align-middle mb-0">
                                <thead class="table-light">
                                    <tr>
                                        <th>Asset</th>
                                        <th>Type</th>
                                        <th>IP Address</th>
                                        <th>Criticality</th>
                                        <th>Location</th>
                                        <th>Department</th>
                                        <th>Owner</th>
                                        <th>Vulnerabilities</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($assets)): ?>
                                        <tr>
                                            <td colspan="9" class="text-center py-4">No assets found matching your criteria</td>
                                        </tr>
                                    <?php else: ?>
                                        <?php foreach ($assets as $asset): ?>
                                            <tr>
                                                <td>
                                                    <div class="fw-bold"><?php echo htmlspecialchars($asset['asset_name']); ?></div>
                                                    <small class="text-muted">ID: <?php echo $asset['asset_id']; ?></small>
                                                </td>
                                                <td>
                                                    <?php 
                                                    $typeIcon = 'server';
                                                    switch ($asset['asset_type']) {
                                                        case 'workstation':
                                                            $typeIcon = 'desktop';
                                                            break;
                                                        case 'network_device':
                                                            $typeIcon = 'network-wired';
                                                            break;
                                                        case 'application':
                                                            $typeIcon = 'window-restore';
                                                            break;
                                                        case 'database':
                                                            $typeIcon = 'database';
                                                            break;
                                                        case 'cloud_service':
                                                            $typeIcon = 'cloud';
                                                            break;
                                                    }
                                                    ?>
                                                    <i class="fas fa-<?php echo $typeIcon; ?> me-1"></i>
                                                    <?php echo ucfirst(str_replace('_', ' ', $asset['asset_type'])); ?>
                                                </td>
                                                <td><?php echo htmlspecialchars($asset['ip_address'] ?: 'N/A'); ?></td>
                                                <td>
                                                    <span class="badge <?php 
                                                        switch ($asset['criticality']) {
                                                            case 'critical': echo 'bg-danger'; break;
                                                            case 'high': echo 'bg-warning text-dark'; break;
                                                            case 'medium': echo 'bg-primary'; break;
                                                            case 'low': echo 'bg-success'; break;
                                                            default: echo 'bg-secondary';
                                                        }
                                                    ?>">
                                                        <?php echo ucfirst($asset['criticality']); ?>
                                                    </span>
                                                </td>
                                                <td><?php echo htmlspecialchars($asset['location'] ?: 'N/A'); ?></td>
                                                <td><?php echo htmlspecialchars($asset['department'] ?: 'N/A'); ?></td>
                                                <td><?php echo htmlspecialchars($asset['owner'] ?: 'N/A'); ?></td>
                                                <td>
                                                    <?php 
                                                    $vulnCount = isset($assetVulnerabilities[$asset['asset_id']]) ? $assetVulnerabilities[$asset['asset_id']] : 0;
                                                    $vulnClass = 'success';
                                                    if ($vulnCount > 5) {
                                                        $vulnClass = 'danger';
                                                    } else if ($vulnCount > 0) {
                                                        $vulnClass = 'warning';
                                                    }
                                                    ?>
                                                    <a href="vulnerabilities.php?asset_id=<?php echo $asset['asset_id']; ?>" class="badge bg-<?php echo $vulnClass; ?> text-decoration-none">
                                                        <?php echo $vulnCount; ?> open
                                                    </a>
                                                </td>
                                                <td>
                                                    <div class="dropdown">
                                                        <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" id="actionDropdown<?php echo $asset['asset_id']; ?>" data-bs-toggle="dropdown" aria-expanded="false">
                                                            <i class="fas fa-ellipsis-v"></i>
                                                        </button>
                                                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="actionDropdown<?php echo $asset['asset_id']; ?>">
                                                            <li><a class="dropdown-item" href="#" data-bs-toggle="modal" data-bs-target="#viewAssetModal" data-asset-id="<?php echo $asset['asset_id']; ?>"><i class="fas fa-eye"></i> View Details</a></li>
                                                            
                                                            <?php if (hasRole('admin', 'manager', 'analyst')): ?>
                                                                <li><a class="dropdown-item" href="#" data-bs-toggle="modal" data-bs-target="#editAssetModal" data-asset-id="<?php echo $asset['asset_id']; ?>"><i class="fas fa-edit"></i> Edit Asset</a></li>
                                                            <?php endif; ?>
                                                            
                                                            <?php if (hasRole('admin', 'manager')): ?>
                                                                <li><hr class="dropdown-divider"></li>
                                                                <li><a class="dropdown-item text-danger delete-asset" href="#" data-asset-id="<?php echo $asset['asset_id']; ?>" data-asset-name="<?php echo htmlspecialchars($asset['asset_name']); ?>"><i class="fas fa-trash-alt"></i> Delete Asset</a></li>
                                                            <?php endif; ?>
                                                            
                                                            <li><hr class="dropdown-divider"></li>
                                                            <li><a class="dropdown-item" href="vulnerabilities.php?asset_id=<?php echo $asset['asset_id']; ?>"><i class="fas fa-bug"></i> View Vulnerabilities</a></li>
                                                            <li><a class="dropdown-item" href="#" data-bs-toggle="modal" data-bs-target="#scanAssetModal" data-asset-id="<?php echo $asset['asset_id']; ?>" data-asset-name="<?php echo htmlspecialchars($asset['asset_name']); ?>"><i class="fas fa-search"></i> Scan Asset</a></li>
                                                        </ul>
                                                    </div>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                        
                        <!-- Pagination -->
                        <?php if ($totalPages > 1): ?>
                            <div class="d-flex justify-content-between align-items-center p-3">
                                <div>
                                    Showing <?php echo $offset + 1; ?> to <?php echo min($offset + $limit, $totalRows); ?> of <?php echo $totalRows; ?> assets
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
    
    <!-- Add Asset Modal -->
    <div class="modal fade" id="addAssetModal" tabindex="-1" aria-labelledby="addAssetModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" name="action" value="add_asset">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="addAssetModalLabel">Add New Asset</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="asset_name" class="form-label">Asset Name <span class="text-danger">*</span></label>
                                <input type="text" class="form-control" id="asset_name" name="asset_name" required>
                            </div>
                            <div class="col-md-6">
                                <label for="asset_type" class="form-label">Asset Type <span class="text-danger">*</span></label>
                                <select class="form-select" id="asset_type" name="asset_type" required>
                                    <option value="">-- Select Type --</option>
                                    <option value="server">Server</option>
                                    <option value="workstation">Workstation</option>
                                    <option value="network_device">Network Device</option>
                                    <option value="application">Application</option>
                                    <option value="database">Database</option>
                                    <option value="cloud_service">Cloud Service</option>
                                    <option value="other">Other</option>
                                </select>
                            </div>
                        </div>
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="ip_address" class="form-label">IP Address</label>
                                <input type="text" class="form-control" id="ip_address" name="ip_address" placeholder="e.g. 192.168.1.1">
                            </div>
                            <div class="col-md-6">
                                <label for="mac_address" class="form-label">MAC Address</label>
                                <input type="text" class="form-control" id="mac_address" name="mac_address" placeholder="e.g. 00:1A:2B:3C:4D:5E">
                            </div>
                        </div>
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="location" class="form-label">Location</label>
                                <input type="text" class="form-control" id="location" name="location">
                            </div>
                            <div class="col-md-6">
                                <label for="department" class="form-label">Department</label>
                                <input type="text" class="form-control" id="department" name="department">
                            </div>
                        </div>
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="owner" class="form-label">Owner/Responsible</label>
                                <input type="text" class="form-control" id="owner" name="owner">
                            </div>
                            <div class="col-md-6">
                                <label for="criticality" class="form-label">Criticality <span class="text-danger">*</span></label>
                                <select class="form-select" id="criticality" name="criticality" required>
                                    <option value="">-- Select Criticality --</option>
                                    <option value="critical">Critical</option>
                                    <option value="high">High</option>
                                    <option value="medium">Medium</option>
                                    <option value="low">Low</option>
                                </select>
                            </div>
                        </div>
                        <div class="mb-3">
                            <label for="description" class="form-label">Description</label>
                            <textarea class="form-control" id="description" name="description" rows="3"></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Asset</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- View Asset Modal -->
    <div class="modal fade" id="viewAssetModal" tabindex="-1" aria-labelledby="viewAssetModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="viewAssetModalLabel">Asset Details</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div id="assetDetailsContent">
                        <div class="text-center">
                            <div class="spinner-border text-primary" role="status">
                                <span class="visually-hidden">Loading...</span>
                            </div>
                            <p class="mt-2">Loading asset details...</p>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    <a href="#" class="btn btn-primary" id="editAssetBtn">Edit Asset</a>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Edit Asset Modal -->
    <div class="modal fade" id="editAssetModal" tabindex="-1" aria-labelledby="editAssetModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" name="action" value="update_asset">
                    <input type="hidden" name="asset_id" id="edit_asset_id" value="">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="editAssetModalLabel">Edit Asset</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="edit_asset_name" class="form-label">Asset Name <span class="text-danger">*</span></label>
                                <input type="text" class="form-control" id="edit_asset_name" name="asset_name" required>
                            </div>
                            <div class="col-md-6">
                                <label for="edit_asset_type" class="form-label">Asset Type <span class="text-danger">*</span></label>
                                <select class="form-select" id="edit_asset_type" name="asset_type" required>
                                    <option value="">-- Select Type --</option>
                                    <option value="server">Server</option>
                                    <option value="workstation">Workstation</option>
                                    <option value="network_device">Network Device</option>
                                    <option value="application">Application</option>
                                    <option value="database">Database</option>
                                    <option value="cloud_service">Cloud Service</option>
                                    <option value="other">Other</option>
                                </select>
                            </div>
                        </div>
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="edit_ip_address" class="form-label">IP Address</label>
                                <input type="text" class="form-control" id="edit_ip_address" name="ip_address" placeholder="e.g. 192.168.1.1">
                            </div>
                            <div class="col-md-6">
                                <label for="edit_mac_address" class="form-label">MAC Address</label>
                                <input type="text" class="form-control" id="edit_mac_address" name="mac_address" placeholder="e.g. 00:1A:2B:3C:4D:5E">
                            </div>
                        </div>
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="edit_location" class="form-label">Location</label>
                                <input type="text" class="form-control" id="edit_location" name="location">
                            </div>
                            <div class="col-md-6">
                                <label for="edit_department" class="form-label">Department</label>
                                <input type="text" class="form-control" id="edit_department" name="department">
                            </div>
                        </div>
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="edit_owner" class="form-label">Owner/Responsible</label>
                                <input type="text" class="form-control" id="edit_owner" name="owner">
                            </div>
                            <div class="col-md-6">
                                <label for="edit_criticality" class="form-label">Criticality <span class="text-danger">*</span></label>
                                <select class="form-select" id="edit_criticality" name="criticality" required>
                                    <option value="">-- Select Criticality --</option>
                                    <option value="critical">Critical</option>
                                    <option value="high">High</option>
                                    <option value="medium">Medium</option>
                                    <option value="low">Low</option>
                                </select>
                            </div>
                        </div>
                        <div class="mb-3">
                            <label for="edit_description" class="form-label">Description</label>
                            <textarea class="form-control" id="edit_description" name="description" rows="3"></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Update Asset</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Scan Asset Modal -->
    <div class="modal fade" id="scanAssetModal" tabindex="-1" aria-labelledby="scanAssetModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <form action="scan-asset.php" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" name="asset_id" id="scan_asset_id" value="">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="scanAssetModalLabel">Scan Asset</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <p>Initiate vulnerability scan for <strong id="scan_asset_name"></strong>?</p>
                        
                        <div class="mb-3">
                            <label for="scan_type" class="form-label">Scan Type</label>
                            <select class="form-select" id="scan_type" name="scan_type" required>
                                <option value="quick">Quick Scan</option>
                                <option value="standard">Standard Scan</option>
                                <option value="full">Full Scan</option>
                            </select>
                            <div class="form-text">Quick scan is faster but may miss vulnerabilities. Full scan is comprehensive but slower.</div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Start Scan</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Export Modal -->
    <div class="modal fade" id="exportModal" tabindex="-1" aria-labelledby="exportModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <form action="export-assets.php" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="exportModalLabel">Export Assets</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="export_format" class="form-label">Format</label>
                            <select class="form-select" id="export_format" name="export_format">
                                <option value="csv">CSV</option>
                                <option value="json">JSON</option>
                                <option value="pdf">PDF</option>
                                <option value="xlsx">Excel (XLSX)</option>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <label for="export_scope" class="form-label">Scope</label>
                            <select class="form-select" id="export_scope" name="export_scope">
                                <option value="filtered">Current filtered results (<?php echo $totalRows; ?> assets)</option>
                                <option value="all">All assets</option>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="include_vulnerabilities" name="include_vulnerabilities" value="1">
                                <label class="form-check-label" for="include_vulnerabilities">
                                    Include vulnerability counts
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
    
    <!-- Delete Asset Form (Hidden) -->
    <form id="deleteAssetForm" method="post" style="display: none;">
        <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
        <input type="hidden" name="action" value="delete_asset">
        <input type="hidden" name="asset_id" id="delete_asset_id" value="">
    </form>
    
    <!-- Include footer -->
    <?php include 'includes/footer.php'; ?>
    
    <!-- Include JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // View asset details
            const viewAssetModal = document.getElementById('viewAssetModal');
            if (viewAssetModal) {
                viewAssetModal.addEventListener('show.bs.modal', function(event) {
                    const button = event.relatedTarget;
                    const assetId = button.getAttribute('data-asset-id');
                    const assetDetailsContent = document.getElementById('assetDetailsContent');
                    const editAssetBtn = document.getElementById('editAssetBtn');
                    
                    // Update edit button link
                    editAssetBtn.setAttribute('data-bs-toggle', 'modal');
                    editAssetBtn.setAttribute('data-bs-target', '#editAssetModal');
                    editAssetBtn.setAttribute('data-asset-id', assetId);
                    
                    // Load asset details via AJAX
                    fetch('get-asset-details.php?id=' + assetId)
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                const asset = data.asset;
                                let criticalityClass = '';
                                switch (asset.criticality) {
                                    case 'critical': criticalityClass = 'danger'; break;
                                    case 'high': criticalityClass = 'warning'; break;
                                    case 'medium': criticalityClass = 'primary'; break;
                                    case 'low': criticalityClass = 'success'; break;
                                    default: criticalityClass = 'secondary';
                                }
                                
                                let html = `
                                    <div class="row">
                                        <div class="col-md-6">
                                            <h5 class="border-bottom pb-2">${asset.asset_name}</h5>
                                            <p><strong>ID:</strong> ${asset.asset_id}</p>
                                            <p><strong>Type:</strong> ${asset.asset_type.replace(/_/g, ' ')}</p>
                                            <p><strong>IP Address:</strong> ${asset.ip_address || 'N/A'}</p>
                                            <p><strong>MAC Address:</strong> ${asset.mac_address || 'N/A'}</p>
                                            <p><strong>Criticality:</strong> <span class="badge bg-${criticalityClass}">${asset.criticality}</span></p>
                                        </div>
                                        <div class="col-md-6">
                                            <h5 class="border-bottom pb-2">Additional Information</h5>
                                            <p><strong>Location:</strong> ${asset.location || 'N/A'}</p>
                                            <p><strong>Department:</strong> ${asset.department || 'N/A'}</p>
                                            <p><strong>Owner:</strong> ${asset.owner || 'N/A'}</p>
                                            <p><strong>Added By:</strong> ${asset.added_by_name || 'N/A'}</p>
                                            <p><strong>Added Date:</strong> ${new Date(asset.created_at).toLocaleString()}</p>
                                        </div>
                                    </div>
                                `;
                                
                                if (asset.description) {
                                    html += `
                                        <div class="row mt-3">
                                            <div class="col-12">
                                                <h5 class="border-bottom pb-2">Description</h5>
                                                <p>${asset.description}</p>
                                            </div>
                                        </div>
                                    `;
                                }
                                
                                // Add vulnerability section if available
                                if (data.vulnerabilities) {
                                    html += `
                                        <div class="row mt-3">
                                            <div class="col-12">
                                                <h5 class="border-bottom pb-2">Vulnerabilities</h5>
                                                <div class="d-flex justify-content-between mb-2">
                                                    <div>Open vulnerabilities: <strong>${data.vulnerabilities.total}</strong></div>
                                                    <a href="vulnerabilities.php?asset_id=${asset.asset_id}" class="btn btn-sm btn-outline-primary">View All</a>
                                                </div>
                                                <div class="row g-2">
                                                    <div class="col-md-3">
                                                        <div class="p-2 border rounded text-center">
                                                            <h6 class="text-danger mb-1">Critical</h6>
                                                            <span class="fs-4">${data.vulnerabilities.critical || 0}</span>
                                                        </div>
                                                    </div>
                                                    <div class="col-md-3">
                                                        <div class="p-2 border rounded text-center">
                                                            <h6 class="text-warning mb-1">High</h6>
                                                            <span class="fs-4">${data.vulnerabilities.high || 0}</span>
                                                        </div>
                                                    </div>
                                                    <div class="col-md-3">
                                                        <div class="p-2 border rounded text-center">
                                                            <h6 class="text-primary mb-1">Medium</h6>
                                                            <span class="fs-4">${data.vulnerabilities.medium || 0}</span>
                                                        </div>
                                                    </div>
                                                    <div class="col-md-3">
                                                        <div class="p-2 border rounded text-center">
                                                            <h6 class="text-success mb-1">Low</h6>
                                                            <span class="fs-4">${data.vulnerabilities.low || 0}</span>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    `;
                                }
                                
                                assetDetailsContent.innerHTML = html;
                            } else {
                                assetDetailsContent.innerHTML = `<div class="alert alert-danger">Error loading asset details: ${data.message}</div>`;
                            }
                        })
                        .catch(error => {
                            assetDetailsContent.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
                        });
                });
            }
            
            // Edit asset modal
            const editAssetModal = document.getElementById('editAssetModal');
            if (editAssetModal) {
                editAssetModal.addEventListener('show.bs.modal', function(event) {
                    const button = event.relatedTarget;
                    const assetId = button.getAttribute('data-asset-id');
                    
                    // Set asset ID in the form
                    document.getElementById('edit_asset_id').value = assetId;
                    
                    // Load asset details via AJAX
                    fetch('get-asset-details.php?id=' + assetId)
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                const asset = data.asset;
                                
                                // Populate form fields
                                document.getElementById('edit_asset_name').value = asset.asset_name;
                                document.getElementById('edit_asset_type').value = asset.asset_type;
                                document.getElementById('edit_ip_address').value = asset.ip_address || '';
                                document.getElementById('edit_mac_address').value = asset.mac_address || '';
                                document.getElementById('edit_location').value = asset.location || '';
                                document.getElementById('edit_department').value = asset.department || '';
                                document.getElementById('edit_owner').value = asset.owner || '';
                                document.getElementById('edit_criticality').value = asset.criticality;
                                document.getElementById('edit_description').value = asset.description || '';
                            } else {
                                alert('Error loading asset details: ' + data.message);
                            }
                        })
                        .catch(error => {
                            alert('Error: ' + error.message);
                        });
                });
            }
            
            // Scan asset modal
            const scanAssetModal = document.getElementById('scanAssetModal');
            if (scanAssetModal) {
                scanAssetModal.addEventListener('show.bs.modal', function(event) {
                    const button = event.relatedTarget;
                    const assetId = button.getAttribute('data-asset-id');
                    const assetName = button.getAttribute('data-asset-name');
                    
                    // Set values in the form
                    document.getElementById('scan_asset_id').value = assetId;
                    document.getElementById('scan_asset_name').textContent = assetName;
                });
            }
            
            // Delete asset
            const deleteButtons = document.querySelectorAll('.delete-asset');
            deleteButtons.forEach(button => {
                button.addEventListener('click', function(e) {
                    e.preventDefault();
                    
                    const assetId = this.getAttribute('data-asset-id');
                    const assetName = this.getAttribute('data-asset-name');
                    
                    if (confirm(`Are you sure you want to delete the asset "${assetName}"? This action cannot be undone.`)) {
                        document.getElementById('delete_asset_id').value = assetId;
                        document.getElementById('deleteAssetForm').submit();
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
</html><?php
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

// Process asset actions
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        $message = "Invalid request";
        $messageType = "danger";
    } else {
        $action = $_POST['action'];
        $userId = $_SESSION['user_id'];
        
        // Add new asset
        if ($action === 'add_asset' && hasRole('admin', 'manager', 'analyst')) {
            $assetName = sanitizeInput($_POST['asset_name']);
            $assetType = sanitizeInput($_POST['asset_type']);
            $ipAddress = sanitizeInput($_POST['ip_address']);
            $macAddress = sanitizeInput($_POST['mac_address']);
            $location = sanitizeInput($_POST['location']);
            $department = sanitizeInput($_POST['department']);
            $owner = sanitizeInput($_POST['owner']);
            $criticality = sanitizeInput($_POST['criticality']);
            $description = sanitizeInput($_POST['description']);
            
            // Validate IP address if provided
            if (!empty($ipAddress) && !filter_var($ipAddress, FILTER_VALIDATE_IP)) {
                $message = "Invalid IP address format";
                $messageType = "danger";
            } 
            // Validate MAC address if provided
            else if (!empty($macAddress) && !preg_match('/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/', $macAddress)) {
                $
           
