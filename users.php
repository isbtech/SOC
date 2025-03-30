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
if (!hasRole('admin', 'manager')) {
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

// Get users
$users = [];
$query = "SELECT * FROM users ORDER BY username";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $users[] = $row;
}

// Close the database connection
$conn->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management - <?php echo SITE_NAME; ?></title>
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
                        <li class="breadcrumb-item active" aria-current="page">User Management</li>
                    </ol>
                </nav>

                <?php if (!empty($message)): ?>
                    <div class="alert alert-<?php echo $messageType; ?> alert-dismissible fade show" role="alert">
                        <?php echo $message; ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                <?php endif; ?>
                
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2"><i class="fas fa-users"></i> User Management</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#addUserModal">
                            <i class="fas fa-user-plus"></i> Add User
                        </button>
                    </div>
                </div>
                
                <!-- Users Table -->
                <div class="card">
                    <div class="card-header bg-white">
                        <h5 class="card-title mb-0">Users</h5>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-hover table-striped align-middle mb-0">
                                <thead class="table-light">
                                    <tr>
                                        <th>Username</th>
                                        <th>Full Name</th>
                                        <th>Email</th>
                                        <th>Role</th>
                                        <th>Status</th>
                                        <th>Last Login</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($users)): ?>
                                        <tr>
                                            <td colspan="7" class="text-center py-4">No users found</td>
                                        </tr>
                                    <?php else: ?>
                                        <?php foreach ($users as $user): ?>
                                            <tr>
                                                <td><?php echo htmlspecialchars($user['username']); ?></td>
                                                <td><?php echo htmlspecialchars($user['first_name'] . ' ' . $user['last_name']); ?></td>
                                                <td><?php echo htmlspecialchars($user['email']); ?></td>
                                                <td>
                                                    <span class="badge <?php 
                                                        switch ($user['role']) {
                                                            case 'admin': echo 'bg-danger'; break;
                                                            case 'manager': echo 'bg-warning text-dark'; break;
                                                            case 'analyst': echo 'bg-primary'; break;
                                                            case 'viewer': echo 'bg-info'; break;
                                                            default: echo 'bg-secondary';
                                                        }
                                                    ?>">
                                                        <?php echo ucfirst($user['role']); ?>
                                                    </span>
                                                </td>
                                                <td>
                                                    <div class="form-check form-switch">
                                                        <input class="form-check-input toggle-user" type="checkbox" role="switch" 
                                                            data-user-id="<?php echo $user['user_id']; ?>" 
                                                            <?php echo $user['is_active'] ? 'checked' : ''; ?>>
                                                    </div>
                                                </td>
                                                <td>
                                                    <?php echo $user['last_login'] ? date('Y-m-d H:i', strtotime($user['last_login'])) : 'Never'; ?>
                                                </td>
                                                <td>
                                                    <div class="btn-group btn-group-sm">
                                                        <button type="button" class="btn btn-outline-primary view-user" data-bs-toggle="modal" data-bs-target="#viewUserModal" data-user-id="<?php echo $user['user_id']; ?>">
                                                            <i class="fas fa-eye"></i>
                                                        </button>
                                                        <button type="button" class="btn btn-outline-secondary edit-user" data-bs-toggle="modal" data-bs-target="#editUserModal" data-user-id="<?php echo $user['user_id']; ?>">
                                                            <i class="fas fa-edit"></i>
                                                        </button>
                                                        <?php if ($user['user_id'] != $_SESSION['user_id']): ?>
                                                            <button type="button" class="btn btn-outline-danger delete-user" data-user-id="<?php echo $user['user_id']; ?>">
                                                                <i class="fas fa-trash-alt"></i>
                                                            </button>
                                                        <?php endif; ?>
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
    
    <!-- Add User Modal -->
    <div class="modal fade" id="addUserModal" tabindex="-1" aria-labelledby="addUserModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <form method="post" action="save-user.php">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" name="action" value="add_user">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="addUserModalLabel">Add User</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="username" class="form-label">Username</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="col-md-6">
                                <label for="email" class="form-label">Email</label>
                                <input type="email" class="form-control" id="email" name="email" required>
                            </div>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="first_name" class="form-label">First Name</label>
                                <input type="text" class="form-control" id="first_name" name="first_name" required>
                            </div>
                            <div class="col-md-6">
                                <label for="last_name" class="form-label">Last Name</label>
                                <input type="text" class="form-control" id="last_name" name="last_name" required>
                            </div>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="password" class="form-label">Password</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                                <div class="form-text">
                                    Password must be at least <?php echo PASSWORD_MIN_LENGTH; ?> characters long and include 
                                    <?php if (PASSWORD_REQUIRES_UPPERCASE): ?>uppercase letters, <?php endif; ?>
                                    <?php if (PASSWORD_REQUIRES_LOWERCASE): ?>lowercase letters, <?php endif; ?>
                                    <?php if (PASSWORD_REQUIRES_NUMBER): ?>numbers, <?php endif; ?>
                                    <?php if (PASSWORD_REQUIRES_SPECIAL): ?>and special characters.<?php endif; ?>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <label for="confirm_password" class="form-label">Confirm Password</label>
                                <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="role" class="form-label">Role</label>
                            <select class="form-select" id="role" name="role" required>
                                <option value="viewer">Viewer</option>
                                <option value="analyst">Analyst</option>
                                <?php if (hasRole('admin')): ?>
                                    <option value="manager">Manager</option>
                                    <option value="admin">Administrator</option>
                                <?php endif; ?>
                            </select>
                        </div>
                        
                        <div class="form-check form-switch mb-3">
                            <input class="form-check-input" type="checkbox" id="is_active" name="is_active" value="1" checked>
                            <label class="form-check-label" for="is_active">Active</label>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add User</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- View User Modal -->
    <div class="modal fade" id="viewUserModal" tabindex="-1" aria-labelledby="viewUserModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="viewUserModalLabel">User Details</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div id="viewUserContent">
                        <div class="text-center py-4">
                            <div class="spinner-border text-primary" role="status">
                                <span class="visually-hidden">Loading...</span>
                            </div>
                            <p class="mt-2">Loading user details...</p>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    <button type="button" class="btn btn-primary edit-from-view" data-bs-toggle="modal" data-bs-target="#editUserModal">Edit User</button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Edit User Modal -->
    <div class="modal fade" id="editUserModal" tabindex="-1" aria-labelledby="editUserModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <form method="post" action="save-user.php">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" name="action" value="update_user">
                    <input type="hidden" name="user_id" id="edit_user_id" value="">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="editUserModalLabel">Edit User</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="edit_username" class="form-label">Username</label>
                                <input type="text" class="form-control" id="edit_username" name="username" required>
                            </div>
                            <div class="col-md-6">
                                <label for="edit_email" class="form-label">Email</label>
                                <input type="email" class="form-control" id="edit_email" name="email" required>
                            </div>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="edit_first_name" class="form-label">First Name</label>
                                <input type="text" class="form-control" id="edit_first_name" name="first_name" required>
                            </div>
                            <div class="col-md-6">
                                <label for="edit_last_name" class="form-label">Last Name</label>
                                <input type="text" class="form-control" id="edit_last_name" name="last_name" required>
                            </div>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="edit_password" class="form-label">New Password (leave blank to keep current)</label>
                                <input type="password" class="form-control" id="edit_password" name="password">
                                <div class="form-text">
                                    Password must be at least <?php echo PASSWORD_MIN_LENGTH; ?> characters long.
                                </div>
                            </div>
                            <div class="col-md-6">
                                <label for="edit_confirm_password" class="form-label">Confirm New Password</label>
                                <input type="password" class="form-control" id="edit_confirm_password" name="confirm_password">
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="edit_role" class="form-label">Role</label>
                            <select class="form-select" id="edit_role" name="role" required>
                                <option value="viewer">Viewer</option>
                                <option value="analyst">Analyst</option>
                                <?php if (hasRole('admin')): ?>
                                    <option value="manager">Manager</option>
                                    <option value="admin">Administrator</option>
                                <?php endif; ?>
                            </select>
                        </div>
                        
                        <div class="form-check form-switch mb-3">
                            <input class="form-check-input" type="checkbox" id="edit_is_active" name="is_active" value="1">
                            <label class="form-check-label" for="edit_is_active">Active</label>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Update User</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Delete User Form (Hidden) -->
    <form id="deleteUserForm" method="post" action="save-user.php" style="display: none;">
        <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
        <input type="hidden" name="action" value="delete_user">
        <input type="hidden" name="user_id" id="delete_user_id" value="">
    </form>
    
    <!-- Include footer -->
    <?php include 'includes/footer.php'; ?>
    
    <!-- Include JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // View user details
            const viewUserModal = document.getElementById('viewUserModal');
            if (viewUserModal) {
                viewUserModal.addEventListener('show.bs.modal', function(event) {
                    const button = event.relatedTarget;
                    const userId = button.getAttribute('data-user-id');
                    const viewUserContent = document.getElementById('viewUserContent');
                    const editFromViewBtn = document.querySelector('.edit-from-view');
                    
                    // Set user ID for edit button
                    editFromViewBtn.setAttribute('data-user-id', userId);
                    
                    // Call API to get user details
                    fetch('get-user-details.php?id=' + userId)
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                const user = data.user;
                                let roleClass = '';
                                
                                switch (user.role) {
                                    case 'admin': roleClass = 'danger'; break;
                                    case 'manager': roleClass = 'warning'; break;
                                    case 'analyst': roleClass = 'primary'; break;
                                    case 'viewer': roleClass = 'info'; break;
                                    default: roleClass = 'secondary';
                                }
                                
                                let html = `
                                    <div class="row">
                                        <div class="col-md-6">
                                            <h5 class="border-bottom pb-2">${user.first_name} ${user.last_name}</h5>
                                            <p><strong>Username:</strong> ${user.username}</p>
                                            <p><strong>Email:</strong> ${user.email}</p>
                                            <p><strong>Role:</strong> <span class="badge bg-${roleClass}">${user.role.toUpperCase()}</span></p>
                                            <p><strong>Status:</strong> 
                                                <span class="badge ${user.is_active == 1 ? 'bg-success' : 'bg-secondary'}">
                                                    ${user.is_active == 1 ? 'Active' : 'Inactive'}
                                                </span>
                                            </p>
                                        </div>
                                        <div class="col-md-6">
                                            <h5 class="border-bottom pb-2">Activity Information</h5>
                                            <p><strong>Last Login:</strong> ${user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}</p>
                                            <p><strong>Date Joined:</strong> ${new Date(user.date_joined).toLocaleString()}</p>
                                        </div>
                                    </div>
                                `;
                                
                                // Add user activity section if available
                                if (data.activity && data.activity.length > 0) {
                                    html += `
                                        <div class="row mt-3">
                                            <div class="col-12">
                                                <h5 class="border-bottom pb-2">Recent Activity</h5>
                                                <div class="table-responsive">
                                                    <table class="table table-sm table-striped">
                                                        <thead>
                                                            <tr>
                                                                <th>Time</th>
                                                                <th>Action</th>
                                                                <th>IP Address</th>
                                                            </tr>
                                                        </thead>
                                                        <tbody>
                                    `;
                                    
                                    data.activity.forEach(activity => {
                                        html += `
                                            <tr>
                                                <td>${new Date(activity.timestamp).toLocaleString()}</td>
                                                <td>${activity.action_type}: ${activity.description}</td>
                                                <td>${activity.ip_address || 'N/A'}</td>
                                            </tr>
                                        `;
                                    });
                                    
                                    html += `
                                                        </tbody>
                                                    </table>
                                                </div>
                                            </div>
                                        </div>
                                    `;
                                }
                                
                                viewUserContent.innerHTML = html;
                            } else {
                                viewUserContent.innerHTML = `<div class="alert alert-danger">Error loading user details: ${data.message}</div>`;
                            }
                        })
                        .catch(error => {
                            viewUserContent.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
                        });
                });
            }
            
            // Edit user
            const editUserModal = document.getElementById('editUserModal');
            if (editUserModal) {
                editUserModal.addEventListener('show.bs.modal', function(event) {
                    const button = event.relatedTarget;
                    const userId = button.getAttribute('data-user-id');
                    
                    // Set user ID in form
                    document.getElementById('edit_user_id').value = userId;
                    
                    // Call API to get user details
                    fetch('get-user-details.php?id=' + userId)
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                const user = data.user;
                                
                                // Populate form fields
                                document.getElementById('edit_username').value = user.username;
                                document.getElementById('edit_email').value = user.email;
                                document.getElementById('edit_first_name').value = user.first_name;
                                document.getElementById('edit_last_name').value = user.last_name;
                                document.getElementById('edit_role').value = user.role;
                                document.getElementById('edit_is_active').checked = user.is_active == 1;
                                
                                // Clear password fields
                                document.getElementById('edit_password').value = '';
                                document.getElementById('edit_confirm_password').value = '';
                            } else {
                                alert('Error loading user details: ' + data.message);
                            }
                        })
                        .catch(error => {
                            alert('Error: ' + error.message);
                        });
                });
            }
            
            // Delete user
            const deleteButtons = document.querySelectorAll('.delete-user');
            deleteButtons.forEach(button => {
                button.addEventListener('click', function() {
                    const userId = this.getAttribute('data-user-id');
                    
                    if (confirm('Are you sure you want to delete this user? This action cannot be undone.')) {
                        document.getElementById('delete_user_id').value = userId;
                        document.getElementById('deleteUserForm').submit();
                    }
                });
            });
            
            // Toggle user active status
            const toggleButtons = document.querySelectorAll('.toggle-user');
            toggleButtons.forEach(button => {
                button.addEventListener('change', function() {
                    const userId = this.getAttribute('data-user-id');
                    const isActive = this.checked ? 1 : 0;
                    
                    // Call API to toggle user status
                    fetch('toggle-user-status.php', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: `user_id=${userId}&is_active=${isActive}&csrf_token=${encodeURIComponent('<?php echo $csrfToken; ?>')}`,
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (!data.success) {
                            alert('Error toggling user status: ' + data.message);
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
        });
    </script>
</body>
</html>