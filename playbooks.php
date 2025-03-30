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
    <title>Playbooks - <?php echo SITE_NAME; ?></title>
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
                        <li class="breadcrumb-item active" aria-current="page">Playbooks</li>
                    </ol>
                </nav>
                
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2"><i class="fas fa-book"></i> Incident Response Playbooks</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <?php if (hasRole('admin', 'manager')): ?>
                        <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#addPlaybookModal">
                            <i class="fas fa-plus"></i> Add Playbook
                        </button>
                        <?php endif; ?>
                    </div>
                </div>
                
                <!-- Incident Types -->
                <div class="row row-cols-1 row-cols-md-3 g-4 mb-4">
                    <div class="col">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title"><i class="fas fa-bug text-danger me-2"></i>Malware Response</h5>
                                <p class="card-text">Standard procedures for responding to malware incidents.</p>
                                <a href="#malware-playbook" class="btn btn-outline-primary" data-bs-toggle="collapse" role="button" aria-expanded="false">
                                    View Playbook
                                </a>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title"><i class="fas fa-fish text-warning me-2"></i>Phishing Response</h5>
                                <p class="card-text">Steps for investigating and remediating phishing attacks.</p>
                                <a href="#phishing-playbook" class="btn btn-outline-primary" data-bs-toggle="collapse" role="button" aria-expanded="false">
                                    View Playbook
                                </a>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title"><i class="fas fa-user-secret text-primary me-2"></i>Unauthorized Access</h5>
                                <p class="card-text">Procedures for handling unauthorized access incidents.</p>
                                <a href="#unauthorized-access-playbook" class="btn btn-outline-primary" data-bs-toggle="collapse" role="button" aria-expanded="false">
                                    View Playbook
                                </a>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title"><i class="fas fa-database text-danger me-2"></i>Data Breach</h5>
                                <p class="card-text">Steps for responding to and containing data breaches.</p>
                                <a href="#data-breach-playbook" class="btn btn-outline-primary" data-bs-toggle="collapse" role="button" aria-expanded="false">
                                    View Playbook
                                </a>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title"><i class="fas fa-server text-warning me-2"></i>Denial of Service</h5>
                                <p class="card-text">Procedures for mitigating denial of service attacks.</p>
                                <a href="#dos-playbook" class="btn btn-outline-primary" data-bs-toggle="collapse" role="button" aria-expanded="false">
                                    View Playbook
                                </a>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title"><i class="fas fa-user-ninja text-primary me-2"></i>Insider Threat</h5>
                                <p class="card-text">Guidelines for investigating and handling insider threats.</p>
                                <a href="#insider-threat-playbook" class="btn btn-outline-primary" data-bs-toggle="collapse" role="button" aria-expanded="false">
                                    View Playbook
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Malware Playbook -->
                <div class="collapse mb-4" id="malware-playbook">
                    <div class="card">
                        <div class="card-header bg-white d-flex justify-content-between align-items-center">
                            <h5 class="card-title mb-0">Malware Response Playbook</h5>
                            <?php if (hasRole('admin', 'manager')): ?>
                            <button type="button" class="btn btn-sm btn-outline-secondary">
                                <i class="fas fa-edit"></i> Edit
                            </button>
                            <?php endif; ?>
                        </div>
                        <div class="card-body">
                            <h6 class="fw-bold">1. Initial Detection and Confirmation</h6>
                            <ul>
                                <li>Review alerts from endpoint detection systems or user-reported issues</li>
                                <li>Validate the alert to confirm it is not a false positive</li>
                                <li>Document initial indicators and symptoms</li>
                                <li>Determine the scope of the infection (single device or multiple systems)</li>
                            </ul>
                            
                            <h6 class="fw-bold">2. Containment</h6>
                            <ul>
                                <li>Isolate affected systems from the network</li>
                                <li>Disable user accounts if necessary</li>
                                <li>Block known IOCs at network and endpoint levels</li>
                                <li>Preserve forensic evidence before remediation</li>
                            </ul>
                            
                            <h6 class="fw-bold">3. Eradication</h6>
                            <ul>
                                <li>Identify and remove malware components</li>
                                <li>Clean or reimage affected systems</li>
                                <li>Scan for persistence mechanisms</li>
                                <li>Verify removal with multiple scanning tools</li>
                            </ul>
                            
                            <h6 class="fw-bold">4. Recovery</h6>
                            <ul>
                                <li>Restore from clean backups if available</li>
                                <li>Apply all necessary security patches</li>
                                <li>Reset compromised credentials</li>
                                <li>Verify system integrity before returning to production</li>
                            </ul>
                            
                            <h6 class="fw-bold">5. Post-Incident Activities</h6>
                            <ul>
                                <li>Conduct a detailed investigation of the root cause</li>
                                <li>Update security measures to prevent similar infections</li>
                                <li>Document lessons learned</li>
                                <li>Update incident response procedures if necessary</li>
                            </ul>
                        </div>
                    </div>
                </div>
                
                <!-- Phishing Playbook -->
                <div class="collapse mb-4" id="phishing-playbook">
                    <div class="card">
                        <div class="card-header bg-white d-flex justify-content-between align-items-center">
                            <h5 class="card-title mb-0">Phishing Response Playbook</h5>
                            <?php if (hasRole('admin', 'manager')): ?>
                            <button type="button" class="btn btn-sm btn-outline-secondary">
                                <i class="fas fa-edit"></i> Edit
                            </button>
                            <?php endif; ?>
                        </div>
                        <div class="card-body">
                            <h6 class="fw-bold">1. Initial Assessment</h6>
                            <ul>
                                <li>Review reported phishing email and user information</li>
                                <li>Analyze email headers, links, and attachments</li>
                                <li>Determine if credentials were entered or files were downloaded</li>
                                <li>Identify other potential victims</li>
                            </ul>
                            
                            <h6 class="fw-bold">2. Containment</h6>
                            <ul>
                                <li>Block phishing domain in email filters, web proxies and DNS</li>
                                <li>Quarantine similar emails across the organization</li>
                                <li>If credential exposure occurred, lock affected accounts</li>
                                <li>If malware was downloaded, isolate affected systems</li>
                            </ul>
                            
                            <h6 class="fw-bold">3. Eradication</h6>
                            <ul>
                                <li>Force password resets for affected accounts</li>
                                <li>Enable additional authentication factors if available</li>
                                <li>Scan systems for indicators of compromise</li>
                                <li>Remove malware if present</li>
                            </ul>
                            
                            <h6 class="fw-bold">4. Recovery</h6>
                            <ul>
                                <li>Restore email access with new credentials</li>
                                <li>Monitor for suspicious activities on affected accounts</li>
                                <li>Verify no unauthorized changes were made</li>
                                <li>Review access logs for all critical systems</li>
                            </ul>
                            
                            <h6 class="fw-bold">5. Post-Incident Activities</h6>
                            <ul>
                                <li>Add phishing indicators to threat intelligence platform</li>
                                <li>Update phishing awareness training materials with example</li>
                                <li>Review email security controls for potential improvements</li>
                                <li>Conduct additional phishing awareness training if needed</li>
                            </ul>
                        </div>
                    </div>
                </div>
                
                <!-- Other playbooks would be similarly structured -->
                
                <!-- Security Playbook Categories -->
                <div class="card mt-4">
                    <div class="card-header bg-white">
                        <h5 class="card-title mb-0">Additional Security Playbooks</h5>
                    </div>
                    <div class="card-body p-0">
                        <div class="list-group list-group-flush">
                            <a href="#" class="list-group-item list-group-item-action">
                                <div class="d-flex w-100 justify-content-between">
                                    <h6 class="mb-1"><i class="fas fa-lock me-2"></i>Account Compromise Playbook</h6>
                                    <small>Updated 3 weeks ago</small>
                                </div>
                                <p class="mb-1 small text-muted">Procedures for investigating and remediating compromised user accounts.</p>
                            </a>
                            <a href="#" class="list-group-item list-group-item-action">
                                <div class="d-flex w-100 justify-content-between">
                                    <h6 class="mb-1"><i class="fas fa-laptop-code me-2"></i>Compromised Web Server Playbook</h6>
                                    <small>Updated 1 month ago</small>
                                </div>
                                <p class="mb-1 small text-muted">Steps for handling compromised web servers and web applications.</p>
                            </a>
                            <a href="#" class="list-group-item list-group-item-action">
                                <div class="d-flex w-100 justify-content-between">
                                    <h6 class="mb-1"><i class="fas fa-euro-sign me-2"></i>Ransomware Response Playbook</h6>
                                    <small>Updated 2 months ago</small>
                                </div>
                                <p class="mb-1 small text-muted">Comprehensive guide for responding to ransomware incidents.</p>
                            </a>
                            <a href="#" class="list-group-item list-group-item-action">
                                <div class="d-flex w-100 justify-content-between">
                                    <h6 class="mb-1"><i class="fas fa-network-wired me-2"></i>Network Device Compromise Playbook</h6>
                                    <small>Updated 2 months ago</small>
                                </div>
                                <p class="mb-1 small text-muted">Procedures for handling compromised network infrastructure.</p>
                            </a>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>
    
    <!-- Add Playbook Modal -->
    <?php if (hasRole('admin', 'manager')): ?>
    <div class="modal fade" id="addPlaybookModal" tabindex="-1" aria-labelledby="addPlaybookModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <form method="post" action="#">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" name="action" value="add_playbook">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="addPlaybookModalLabel">Add New Playbook</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="playbook_title" class="form-label">Playbook Title</label>
                            <input type="text" class="form-control" id="playbook_title" name="playbook_title" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="incident_type" class="form-label">Incident Type</label>
                            <select class="form-select" id="incident_type" name="incident_type" required>
                                <option value="">-- Select Type --</option>
                                <option value="malware">Malware</option>
                                <option value="phishing">Phishing</option>
                                <option value="unauthorized_access">Unauthorized Access</option>
                                <option value="data_breach">Data Breach</option>
                                <option value="denial_of_service">Denial of Service</option>
                                <option value="insider_threat">Insider Threat</option>
                                <option value="other">Other</option>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <label for="playbook_content" class="form-label">Playbook Content</label>
                            <div id="playbook-editor" style="height: 400px; border: 1px solid #ccc; border-radius: 4px;"></div>
                            <textarea class="form-control d-none" id="playbook_content" name="playbook_content" rows="10"></textarea>
                        </div>
                        
                        <div class="mb-3">
                            <label for="playbook_tags" class="form-label">Tags</label>
                            <input type="text" class="form-control" id="playbook_tags" name="playbook_tags" placeholder="e.g. ransomware, forensics, windows">
                            <div class="form-text">Separate tags with commas</div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Playbook</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- Include footer -->
    <?php include 'includes/footer.php'; ?>
    
    <!-- Include JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <?php if (hasRole('admin', 'manager')): ?>
    <!-- Include rich text editor -->
    <link href="https://cdn.quilljs.com/1.3.6/quill.snow.css" rel="stylesheet">
    <script src="https://cdn.quilljs.com/1.3.6/quill.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Initialize Quill editor
            if (document.getElementById('playbook-editor')) {
                const quill = new Quill('#playbook-editor', {
                    theme: 'snow',
                    modules: {
                        toolbar: [
                            [{ 'header': [1, 2, 3, 4, 5, 6, false] }],
                            ['bold', 'italic', 'underline', 'strike'],
                            [{ 'list': 'ordered' }, { 'list': 'bullet' }],
                            [{ 'color': [] }, { 'background': [] }],
                            ['link', 'image'],
                            ['clean']
                        ]
                    }
                });
                
                // Update hidden textarea before form submission
                document.querySelector('form').addEventListener('submit', function() {
                    document.getElementById('playbook_content').value = quill.root.innerHTML;
                });
            }
        });
    </script>
    <?php endif; ?>
</body>
</html>