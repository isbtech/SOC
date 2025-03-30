<?php
require_once 'config.php';

// Initialize secure session
initSecureSession();

// Check if user is authenticated, redirect to login if not
if (!isAuthenticated()) {
    header("Location: index.php");
    exit;
}

// Check if user has permission
if (!hasRole('admin', 'manager', 'analyst')) {
    $_SESSION['error_message'] = "You don't have permission to access this page.";
    header("Location: dashboard.php");
    exit;
}

// Connect to database
$conn = connectDB();

// Process form submissions
$message = '';
$messageType = '';

// Generate CSRF token for forms
$csrfToken = generateCSRFToken();

// Get alert rules
$rules = [];
$query = "SELECT rule_id, rule_name, description, rule_condition, severity, is_active, 
         created_at, updated_at, u.username as created_by_name
         FROM alert_rules r
         LEFT JOIN users u ON r.created_by = u.user_id
         ORDER BY rule_name";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $rules[] = $row;
}

// Close the database connection
$conn->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Alert Rules - <?php echo SITE_NAME; ?></title>
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
                        <li class="breadcrumb-item active" aria-current="page">Alert Rules</li>
                    </ol>
                </nav>

                <?php if (!empty($message)): ?>
                    <div class="alert alert-<?php echo $messageType; ?> alert-dismissible fade show" role="alert">
                        <?php echo $message; ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                <?php endif; ?>
                
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2"><i class="fas fa-cogs"></i> Alert Rules</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#addRuleModal">
                            <i class="fas fa-plus"></i> Add Rule
                        </button>
                    </div>
                </div>
                
                <!-- Quick Statistics -->
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="card bg-primary text-white h-100">
                            <div class="card-body d-flex align-items-center justify-content-between">
                                <div>
                                    <h6 class="card-title mb-0">Total Rules</h6>
                                    <h2 class="mt-2 mb-0"><?php echo count($rules); ?></h2>
                                </div>
                                <i class="fas fa-list-ul fa-2x"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-success text-white h-100">
                            <div class="card-body d-flex align-items-center justify-content-between">
                                <div>
                                    <h6 class="card-title mb-0">Active Rules</h6>
                                    <h2 class="mt-2 mb-0"><?php echo count(array_filter($rules, function($rule) { return $rule['is_active'] == 1; })); ?></h2>
                                </div>
                                <i class="fas fa-toggle-on fa-2x"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-danger text-white h-100">
                            <div class="card-body d-flex align-items-center justify-content-between">
                                <div>
                                    <h6 class="card-title mb-0">Critical Rules</h6>
                                    <h2 class="mt-2 mb-0"><?php echo count(array_filter($rules, function($rule) { return $rule['severity'] == 'critical'; })); ?></h2>
                                </div>
                                <i class="fas fa-exclamation-triangle fa-2x"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-warning text-dark h-100">
                            <div class="card-body d-flex align-items-center justify-content-between">
                                <div>
                                    <h6 class="card-title mb-0">High Rules</h6>
                                    <h2 class="mt-2 mb-0"><?php echo count(array_filter($rules, function($rule) { return $rule['severity'] == 'high'; })); ?></h2>
                                </div>
                                <i class="fas fa-exclamation-circle fa-2x"></i>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Rules Table -->
                <div class="card">
                    <div class="card-header bg-white">
                        <h5 class="card-title mb-0">Alert Rules</h5>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-hover table-striped align-middle mb-0">
                                <thead class="table-light">
                                    <tr>
                                        <th>Rule Name</th>
                                        <th>Description</th>
                                        <th>Severity</th>
                                        <th>Status</th>
                                        <th>Created By</th>
                                        <th>Created At</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($rules)): ?>
                                        <tr>
                                            <td colspan="7" class="text-center py-4">No alert rules found</td>
                                        </tr>
                                    <?php else: ?>
                                        <?php foreach ($rules as $rule): ?>
                                            <tr>
                                                <td><?php echo htmlspecialchars($rule['rule_name']); ?></td>
                                                <td>
                                                    <?php 
                                                    $description = $rule['description'] ?: 'No description';
                                                    echo htmlspecialchars(substr($description, 0, 50)) . (strlen($description) > 50 ? '...' : ''); 
                                                    ?>
                                                </td>
                                                <td>
                                                    <span class="badge <?php 
                                                        switch ($rule['severity']) {
                                                            case 'critical': echo 'bg-danger'; break;
                                                            case 'high': echo 'bg-warning text-dark'; break;
                                                            case 'medium': echo 'bg-primary'; break;
                                                            case 'low': echo 'bg-success'; break;
                                                            default: echo 'bg-info';
                                                        }
                                                    ?>">
                                                        <?php echo ucfirst($rule['severity']); ?>
                                                    </span>
                                                </td>
                                                <td>
                                                    <div class="form-check form-switch">
                                                        <input class="form-check-input toggle-rule" type="checkbox" role="switch" 
                                                            data-rule-id="<?php echo $rule['rule_id']; ?>" 
                                                            <?php echo $rule['is_active'] ? 'checked' : ''; ?>>
                                                    </div>
                                                </td>
                                                <td><?php echo htmlspecialchars($rule['created_by_name'] ?: 'System'); ?></td>
                                                <td><?php echo date('Y-m-d', strtotime($rule['created_at'])); ?></td>
                                                <td>
                                                    <div class="btn-group btn-group-sm">
                                                        <button type="button" class="btn btn-outline-primary view-rule" data-bs-toggle="modal" data-bs-target="#viewRuleModal" data-rule-id="<?php echo $rule['rule_id']; ?>">
                                                            <i class="fas fa-eye"></i>
                                                        </button>
                                                        <button type="button" class="btn btn-outline-secondary edit-rule" data-bs-toggle="modal" data-bs-target="#editRuleModal" data-rule-id="<?php echo $rule['rule_id']; ?>">
                                                            <i class="fas fa-edit"></i>
                                                        </button>
                                                        <button type="button" class="btn btn-outline-danger delete-rule" data-rule-id="<?php echo $rule['rule_id']; ?>">
                                                            <i class="fas fa-trash-alt"></i>
                                                        </button>
                                                    </div>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>
    
    <!-- Add Rule Modal -->
    <div class="modal fade" id="addRuleModal" tabindex="-1" aria-labelledby="addRuleModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <form method="post" action="save-rule.php">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" name="action" value="add_rule">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="addRuleModalLabel">Add Alert Rule</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="rule_name" class="form-label">Rule Name</label>
                            <input type="text" class="form-control" id="rule_name" name="rule_name" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="description" class="form-label">Description</label>
                            <textarea class="form-control" id="description" name="description" rows="2"></textarea>
                        </div>
                        
                        <div class="mb-3">
                            <label for="severity" class="form-label">Severity</label>
                            <select class="form-select" id="severity" name="severity" required>
                                <option value="critical">Critical</option>
                                <option value="high">High</option>
                                <option value="medium">Medium</option>
                                <option value="low">Low</option>
                                <option value="informational">Informational</option>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <label for="rule_condition" class="form-label">Rule Condition</label>
                            <textarea class="form-control" id="rule_condition" name="rule_condition" rows="5" required></textarea>
                            <div class="form-text">Define the rule condition using the rule language syntax. See documentation for details.</div>
                        </div>
                        
                        <div class="form-check form-switch mb-3">
                            <input class="form-check-input" type="checkbox" id="is_active" name="is_active" value="1" checked>
                            <label class="form-check-label" for="is_active">Active</label>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Rule</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- View Rule Modal -->
    <div class="modal fade" id="viewRuleModal" tabindex="-1" aria-labelledby="viewRuleModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="viewRuleModalLabel">Rule Details</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div id="viewRuleContent">
                        <div class="text-center py-4">
                            <div class="spinner-border text-primary" role="status">
                                <span class="visually-hidden">Loading...</span>
                            </div>
                            <p class="mt-2">Loading rule details...</p>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    <button type="button" class="btn btn-primary edit-from-view" data-bs-toggle="modal" data-bs-target="#editRuleModal">Edit Rule</button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Edit Rule Modal -->
    <div class="modal fade" id="editRuleModal" tabindex="-1" aria-labelledby="editRuleModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <form method="post" action="save-rule.php">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" name="action" value="update_rule">
                    <input type="hidden" name="rule_id" id="edit_rule_id" value="">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="editRuleModalLabel">Edit Alert Rule</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="edit_rule_name" class="form-label">Rule Name</label>
                            <input type="text" class="form-control" id="edit_rule_name" name="rule_name" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="edit_description" class="form-label">Description</label>
                            <textarea class="form-control" id="edit_description" name="description" rows="2"></textarea>
                        </div>
                        
                        <div class="mb-3">
                            <label for="edit_severity" class="form-label">Severity</label>
                            <select class="form-select" id="edit_severity" name="severity" required>
                                <option value="critical">Critical</option>
                                <option value="high">High</option>
                                <option value="medium">Medium</option>
                                <option value="low">Low</option>
                                <option value="informational">Informational</option>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <label for="edit_rule_condition" class="form-label">Rule Condition</label>
                            <textarea class="form-control" id="edit_rule_condition" name="rule_condition" rows="5" required></textarea>
                            <div class="form-text">Define the rule condition using the rule language syntax. See documentation for details.</div>
                        </div>
                        
                        <div class="form-check form-switch mb-3">
                            <input class="form-check-input" type="checkbox" id="edit_is_active" name="is_active" value="1">
                            <label class="form-check-label" for="edit_is_active">Active</label>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Update Rule</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Delete Rule Form (Hidden) -->
    <form id="deleteRuleForm" method="post" action="save-rule.php" style="display: none;">
        <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
        <input type="hidden" name="action" value="delete_rule">
        <input type="hidden" name="rule_id" id="delete_rule_id" value="">
    </form>
    
    <!-- Include footer -->
    <?php include 'includes/footer.php'; ?>
    
    <!-- Include JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // View rule details
            const viewRuleModal = document.getElementById('viewRuleModal');
            if (viewRuleModal) {
                viewRuleModal.addEventListener('show.bs.modal', function(event) {
                    const button = event.relatedTarget;
                    const ruleId = button.getAttribute('data-rule-id');
                    const viewRuleContent = document.getElementById('viewRuleContent');
                    const editFromViewBtn = document.querySelector('.edit-from-view');
                    
                    // Set rule ID for edit button
                    editFromViewBtn.setAttribute('data-rule-id', ruleId);
                    
                    // Call API to get rule details
                    fetch('get-rule-details.php?id=' + ruleId)
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                const rule = data.rule;
                                let severityClass = getSeverityClass(rule.severity);
                                
                                let html = `
                                    <div class="row">
                                        <div class="col-md-6">
                                            <h5 class="border-bottom pb-2">${rule.rule_name}</h5>
                                            <p><strong>ID:</strong> ${rule.rule_id}</p>
                                            <p><strong>Severity:</strong> <span class="badge bg-${severityClass}">${rule.severity.toUpperCase()}</span></p>
                                            <p><strong>Status:</strong> 
                                                <span class="badge ${rule.is_active == 1 ? 'bg-success' : 'bg-secondary'}">
                                                    ${rule.is_active == 1 ? 'Active' : 'Inactive'}
                                                </span>
                                            </p>
                                        </div>
                                        <div class="col-md-6">
                                            <h5 class="border-bottom pb-2">Additional Information</h5>
                                            <p><strong>Created By:</strong> ${rule.created_by_name || 'System'}</p>
                                            <p><strong>Created At:</strong> ${new Date(rule.created_at).toLocaleString()}</p>
                                            <p><strong>Updated At:</strong> ${rule.updated_at ? new Date(rule.updated_at).toLocaleString() : 'Never'}</p>
                                        </div>
                                    </div>
                                `;
                                
                                if (rule.description) {
                                    html += `
                                        <div class="row mt-3">
                                            <div class="col-12">
                                                <h5 class="border-bottom pb-2">Description</h5>
                                                <p>${rule.description}</p>
                                            </div>
                                        </div>
                                    `;
                                }
                                
                                html += `
                                    <div class="row mt-3">
                                        <div class="col-12">
                                            <h5 class="border-bottom pb-2">Rule Condition</h5>
                                            <pre class="bg-light p-3 rounded">${rule.rule_condition}</pre>
                                        </div>
                                    </div>
                                `;
                                
                                viewRuleContent.innerHTML = html;
                            } else {
                                viewRuleContent.innerHTML = `<div class="alert alert-danger">Error loading rule details: ${data.message}</div>`;
                            }
                        })
                        .catch(error => {
                            viewRuleContent.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
                        });
                });
            }
            
            // Edit rule
            const editRuleModal = document.getElementById('editRuleModal');
            if (editRuleModal) {
                editRuleModal.addEventListener('show.bs.modal', function(event) {
                    const button = event.relatedTarget;
                    const ruleId = button.getAttribute('data-rule-id');
                    
                    // Set rule ID in form
                    document.getElementById('edit_rule_id').value = ruleId;
                    
                    // Call API to get rule details
                    fetch('get-rule-details.php?id=' + ruleId)
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                const rule = data.rule;
                                
                                // Populate form fields
                                document.getElementById('edit_rule_name').value = rule.rule_name;
                                document.getElementById('edit_description').value = rule.description || '';
                                document.getElementById('edit_severity').value = rule.severity;
                                document.getElementById('edit_rule_condition').value = rule.rule_condition;
                                document.getElementById('edit_is_active').checked = rule.is_active == 1;
                            } else {
                                alert('Error loading rule details: ' + data.message);
                            }
                        })
                        .catch(error => {
                            alert('Error: ' + error.message);
                        });
                });
            }
            
            // Delete rule
            const deleteButtons = document.querySelectorAll('.delete-rule');
            deleteButtons.forEach(button => {
                button.addEventListener('click', function() {
                    const ruleId = this.getAttribute('data-rule-id');
                    
                    if (confirm('Are you sure you want to delete this rule? This action cannot be undone.')) {
                        document.getElementById('delete_rule_id').value = ruleId;
                        document.getElementById('deleteRuleForm').submit();
                    }
                });
            });
            
            // Toggle rule active status
            const toggleButtons = document.querySelectorAll('.toggle-rule');
            toggleButtons.forEach(button => {
                button.addEventListener('change', function() {
                    const ruleId = this.getAttribute('data-rule-id');
                    const isActive = this.checked ? 1 : 0;
                    
                    // Call API to toggle rule status
                    fetch('toggle-rule-status.php', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: `rule_id=${ruleId}&is_active=${isActive}&csrf_token=${encodeURIComponent('<?php echo $csrfToken; ?>')}`,
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (!data.success) {
                            alert('Error toggling rule status: ' + data.message);
                            // Revert the toggle if there was an error
                            this.checked = !this.checked;
                        }
                    })
                    .catch(error => {
                        alert('Error: ' + error.message);
                        // Revert the toggle if there was an error
                        this.checked = !this.checked;
                    });
                });
            });
            
            // Helper function to get severity class
            function getSeverityClass(severity) {
                switch (severity) {
                    case 'critical': return 'danger';
                    case 'high': return 'warning';
                    case 'medium': return 'primary';
                    case 'low': return 'success';
                    default: return 'info';
                }
            }
        });
    </script>
</body>
</html>