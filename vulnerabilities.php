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
                                <option value="filtered">Current filtered results (<?php echo $totalRows; ?> vulnerabilities)</option>
                                <option value="selected">Selected vulnerabilities only</option>
                                <option value="all">All vulnerabilities</option>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="include_remediation" name="include_remediation" value="1" checked>
                                <label class="form-check-label" for="include_remediation">
                                    Include remediation steps
                                </label>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="include_status_history" name="include_status_history" value="1">
                                <label class="form-check-label" for="include_status_history">
                                    Include status history
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
    
    <!-- Include footer -->
    <?php include 'includes/footer.php'; ?>
    
    <!-- Include JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Initialize date pickers
            flatpickr('.datepicker', {
                dateFormat: 'Y-m-d',
                allowInput: true
            });
            
            // Select all checkbox functionality
            document.getElementById('selectAll').addEventListener('change', function() {
                const isChecked = this.checked;
                document.querySelectorAll('.vuln-checkbox').forEach(function(checkbox) {
                    checkbox.checked = isChecked;
                });
            });
            
            // View vulnerability details
            const viewVulnerabilityModal = document.getElementById('viewVulnerabilityModal');
            if (viewVulnerabilityModal) {
                viewVulnerabilityModal.addEventListener('show.bs.modal', function(event) {
                    const button = event.relatedTarget || document.querySelector('.view-vulnerability[data-vuln-id="' + event.currentTarget.getAttribute('data-vuln-id') + '"]');
                    const vulnId = button.getAttribute('data-vuln-id');
                    const vulnerabilityDetailsContent = document.getElementById('vulnerabilityDetailsContent');
                    const editVulnBtn = document.getElementById('editVulnBtn');
                    
                    // Update edit button
                    editVulnBtn.setAttribute('data-bs-toggle', 'modal');
                    editVulnBtn.setAttribute('data-bs-target', '#editVulnerabilityModal');
                    editVulnBtn.setAttribute('data-vuln-id', vulnId);
                    
                    // Load vulnerability details via AJAX
                    fetch('get-vulnerability-details.php?id=' + vulnId)
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                const vuln = data.vulnerability;
                                let severityClass = '';
                                switch (vuln.severity) {
                                    case 'critical': severityClass = 'danger'; break;
                                    case 'high': severityClass = 'warning'; break;
                                    case 'medium': severityClass = 'primary'; break;
                                    case 'low': severityClass = 'success'; break;
                                    default: severityClass = 'info';
                                }
                                
                                let statusClass = '';
                                switch (vuln.status) {
                                    case 'open': statusClass = 'danger'; break;
                                    case 'in_progress': statusClass = 'warning'; break;
                                    case 'mitigated': statusClass = 'primary'; break;
                                    case 'resolved': statusClass = 'success'; break;
                                    case 'accepted_risk': statusClass = 'secondary'; break;
                                    default: statusClass = 'info';
                                }
                                
                                let html = `
                                    <div class="row">
                                        <div class="col-md-6">
                                            <h5 class="border-bottom pb-2">${vuln.vuln_name}</h5>
                                            <p class="mb-2"><span class="badge bg-${severityClass} mb-1">${vuln.severity.toUpperCase()}</span> <span class="badge bg-${statusClass} mb-1">${vuln.status.replace('_', ' ').toUpperCase()}</span></p>
                                            <p><strong>CVE ID:</strong> ${vuln.cve_id ? `<a href="https://nvd.nist.gov/vuln/detail/${vuln.cve_id}" target="_blank">${vuln.cve_id} <i class="fas fa-external-link-alt fa-xs"></i></a>` : 'N/A'}</p>
                                            <p><strong>Asset:</strong> <a href="assets.php?asset_id=${vuln.asset_id}">${vuln.asset_name}</a></p>
                                            <p><strong>Discovered:</strong> ${new Date(vuln.discovered_at).toLocaleString()}</p>
                                            ${vuln.resolved_at ? `<p><strong>Resolved:</strong> ${new Date(vuln.resolved_at).toLocaleString()}</p>` : ''}
                                        </div>
                                        <div class="col-md-6">
                                            <h5 class="border-bottom pb-2">Asset Information</h5>
                                            <p><strong>Asset Type:</strong> ${vuln.asset_type.replace('_', ' ')}</p>
                                            <p><strong>IP Address:</strong> ${vuln.ip_address || 'N/A'}</p>
                                            <p><strong>Criticality:</strong> <span class="badge bg-${getAssetCriticalityClass(vuln.asset_criticality)}">${vuln.asset_criticality}</span></p>
                                            <p><strong>Department:</strong> ${vuln.department || 'N/A'}</p>
                                            <p><strong>Location:</strong> ${vuln.location || 'N/A'}</p>
                                        </div>
                                    </div>
                                `;
                                
                                if (vuln.description) {
                                    html += `
                                        <div class="row mt-3">
                                            <div class="col-12">
                                                <h5 class="border-bottom pb-2">Description</h5>
                                                <p>${vuln.description}</p>
                                            </div>
                                        </div>
                                    `;
                                }
                                
                                if (vuln.remediation) {
                                    html += `
                                        <div class="row mt-3">
                                            <div class="col-12">
                                                <h5 class="border-bottom pb-2">Remediation Steps</h5>
                                                <p>${vuln.remediation}</p>
                                            </div>
                                        </div>
                                    `;
                                }
                                
                                // Add status history if available
                                if (data.status_history && data.status_history.length > 0) {
                                    html += `
                                        <div class="row mt-3">
                                            <div class="col-12">
                                                <h5 class="border-bottom pb-2">Status History</h5>
                                                <div class="table-responsive">
                                                    <table class="table table-sm table-striped">
                                                        <thead>
                                                            <tr>
                                                                <th>Date</th>
                                                                <th>Status Change</th>
                                                                <th>Changed By</th>
                                                                <th>Notes</th>
                                                            </tr>
                                                        </thead>
                                                        <tbody>
                                    `;
                                    
                                    data.status_history.forEach(history => {
                                        html += `
                                            <tr>
                                                <td>${new Date(history.changed_at).toLocaleString()}</td>
                                                <td>${history.previous_status.replace('_', ' ')} → ${history.new_status.replace('_', ' ')}</td>
                                                <td>${history.username}</td>
                                                <td>${history.notes || 'N/A'}</td>
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
                                
                                vulnerabilityDetailsContent.innerHTML = html;
                            } else {
                                vulnerabilityDetailsContent.innerHTML = `<div class="alert alert-danger">Error loading vulnerability details: ${data.message}</div>`;
                            }
                        })
                        .catch(error => {
                            vulnerabilityDetailsContent.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
                        });
                });
            }
            
            // Edit vulnerability modal
            const editVulnerabilityModal = document.getElementById('editVulnerabilityModal');
            if (editVulnerabilityModal) {
                editVulnerabilityModal.addEventListener('show.bs.modal', function(event) {
                    const button = event.relatedTarget;
                    const vulnId = button.getAttribute('data-vuln-id');
                    
                    // Set vulnerability ID in the form
                    document.getElementById('edit_vuln_id').value = vulnId;
                    
                    // Load vulnerability details via AJAX
                    fetch('get-vulnerability-details.php?id=' + vulnId)
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                const vuln = data.vulnerability;
                                
                                // Populate form fields
                                document.getElementById('edit_vuln_name').value = vuln.vuln_name;
                                document.getElementById('edit_cve_id').value = vuln.cve_id || '';
                                document.getElementById('edit_asset_id').value = vuln.asset_id;
                                document.getElementById('edit_severity').value = vuln.severity;
                                document.getElementById('edit_description').value = vuln.description || '';
                                document.getElementById('edit_remediation').value = vuln.remediation || '';
                            } else {
                                alert('Error loading vulnerability details: ' + data.message);
                            }
                        })
                        .catch(error => {
                            alert('Error: ' + error.message);
                        });
                });
            }
            
            // Resolve vulnerability modal
            const resolveVulnerabilityModal = document.getElementById('resolveVulnerabilityModal');
            if (resolveVulnerabilityModal) {
                resolveVulnerabilityModal.addEventListener('show.bs.modal', function(event) {
                    const button = event.relatedTarget;
                    const vulnId = button.getAttribute('data-vuln-id');
                    
                    // Set vulnerability ID in the form
                    document.getElementById('resolve_vuln_id').value = vulnId;
                });
            }
            
            // Accept risk modal
            const acceptRiskModal = document.getElementById('acceptRiskModal');
            if (acceptRiskModal) {
                acceptRiskModal.addEventListener('show.bs.modal', function(event) {
                    const button = event.relatedTarget;
                    const vulnId = button.getAttribute('data-vuln-id');
                    
                    // Set vulnerability ID in the form
                    document.getElementById('risk_vuln_id').value = vulnId;
                });
            }
            
            // Quick status update
            const updateStatusButtons = document.querySelectorAll('.update-status');
            updateStatusButtons.forEach(button => {
                button.addEventListener('click', function(e) {
                    e.preventDefault();
                    
                    const vulnId = this.getAttribute('data-vuln-id');
                    const status = this.getAttribute('data-status');
                    
                    // Set values in the form
                    document.getElementById('status_vuln_id').value = vulnId;
                    document.getElementById('new_status').value = status;
                    
                    // Confirm before submission
                    if (confirm(`Are you sure you want to change the status to ${status.replace('_', ' ')}?`)) {
                        document.getElementById('updateStatusForm').submit();
                    }
                });
            });
            
            // Bulk actions
            const bulkActionButtons = document.querySelectorAll('.bulk-action');
            const bulkUpdateModal = new bootstrap.Modal(document.getElementById('bulkUpdateModal'));
            
            bulkActionButtons.forEach(button => {
                button.addEventListener('click', function(e) {
                    e.preventDefault();
                    
                    // Check if any vulnerabilities are selected
                    const checkedBoxes = document.querySelectorAll('.vuln-checkbox:checked');
                    if (checkedBoxes.length === 0) {
                        alert('Please select at least one vulnerability.');
                        return;
                    }
                    
                    // Set the action type
                    const status = this.getAttribute('data-status');
                    document.getElementById('bulkActionField').value = status;
                    
                    // Update modal title
                    document.getElementById('bulkUpdateModalLabel').textContent = `Mark ${checkedBoxes.length} Vulnerabilities as ${status.replace('_', ' ')}`;
                    
                    // Show modal
                    bulkUpdateModal.show();
                });
            });
            
            // Refresh button
            document.getElementById('refreshBtn').addEventListener('click', function() {
                window.location.reload();
            });
            
            // Helper function to get asset criticality class
            function getAssetCriticalityClass(criticality) {
                switch (criticality) {
                    case 'critical': return 'danger';
                    case 'high': return 'warning';
                    case 'medium': return 'primary';
                    case 'low': return 'success';
                    default: return 'secondary';
                }
            }
        });
    </script>
</body>
</html>="d-flex flex-wrap align-items-center">
                                    <div class="form-check me-3">
                                        <input class="form-check-input" type="checkbox" id="selectAll">
                                        <label class="form-check-label" for="selectAll">Select All</label>
                                    </div>
                                    
                                    <?php if (hasRole('admin', 'manager', 'analyst')): ?>
                                    <div class="dropdown me-3">
                                        <button class="btn btn-outline-secondary dropdown-toggle" type="button" id="bulkActionDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                                            Bulk Actions
                                        </button>
                                        <ul class="dropdown-menu" aria-labelledby="bulkActionDropdown">
                                            <li><a class="dropdown-item bulk-action" href="#" data-status="in_progress">Mark as In Progress</a></li>
                                            <li><a class="dropdown-item bulk-action" href="#" data-status="mitigated">Mark as Mitigated</a></li>
                                            <li><a class="dropdown-item bulk-action" href="#" data-status="resolved">Mark as Resolved</a></li>
                                            <li><a class="dropdown-item bulk-action" href="#" data-status="accepted_risk">Mark as Accepted Risk</a></li>
                                        </ul>
                                    </div>
                                    <?php endif; ?>
                                    
                                    <div class="ms-auto">
                                        <span class="text-muted">
                                            <?php echo $totalRows; ?> vulnerability(ies) found
                                        </span>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="table-responsive">
                                <table class="table table-hover align-middle mb-0">
                                    <thead class="table-light">
                                        <tr>
                                            <th style="width: 40px;"></th>
                                            <th style="width: 100px;">Severity</th>
                                            <th>Vulnerability</th>
                                            <th style="width: 200px;">Asset</th>
                                            <th style="width: 130px;">CVE ID</th>
                                            <th style="width: 130px;">Status</th>
                                            <th style="width: 170px;">Discovered</th>
                                            <th style="width: 100px;">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php if (empty($vulnerabilities)): ?>
                                            <tr>
                                                <td colspan="8" class="text-center py-4">No vulnerabilities found matching your criteria</td>
                                            </tr>
                                        <?php else: ?>
                                            <?php foreach ($vulnerabilities as $vuln): ?>
                                                <tr>
                                                    <td>
                                                        <div class="form-check">
                                                            <input class="form-check-input vuln-checkbox" type="checkbox" name="selected_vulnerabilities[]" value="<?php echo $vuln['vuln_id']; ?>">
                                                        </div>
                                                    </td>
                                                    <td>
                                                        <span class="badge <?php 
                                                            switch ($vuln['severity']) {
                                                                case 'critical': echo 'bg-danger'; break;
                                                                case 'high': echo 'bg-warning text-dark'; break;
                                                                case 'medium': echo 'bg-primary'; break;
                                                                case 'low': echo 'bg-success'; break;
                                                                default: echo 'bg-info';
                                                            }
                                                        ?>">
                                                            <?php echo ucfirst($vuln['severity']); ?>
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <a href="#" class="text-decoration-none view-vulnerability" data-bs-toggle="modal" data-bs-target="#viewVulnerabilityModal" data-vuln-id="<?php echo $vuln['vuln_id']; ?>">
                                                            <?php echo htmlspecialchars($vuln['vuln_name']); ?>
                                                        </a>
                                                        <?php if (!empty($vuln['description'])): ?>
                                                            <div class="small text-muted text-truncate" style="max-width: 300px;"><?php echo htmlspecialchars(substr($vuln['description'], 0, 100)) . (strlen($vuln['description']) > 100 ? '...' : ''); ?></div>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td>
                                                        <a href="assets.php?asset_id=<?php echo $vuln['asset_id']; ?>" class="text-decoration-none">
                                                            <?php echo htmlspecialchars($vuln['asset_name']); ?>
                                                        </a>
                                                        <?php if (!empty($vuln['ip_address'])): ?>
                                                            <div class="small text-muted"><?php echo htmlspecialchars($vuln['ip_address']); ?></div>
                                                        <?php endif; ?>
                                                        <span class="badge <?php 
                                                            switch ($vuln['asset_criticality']) {
                                                                case 'critical': echo 'bg-danger'; break;
                                                                case 'high': echo 'bg-warning text-dark'; break;
                                                                case 'medium': echo 'bg-primary'; break;
                                                                case 'low': echo 'bg-success'; break;
                                                                default: echo 'bg-secondary';
                                                            }
                                                        ?>">
                                                            <?php echo ucfirst($vuln['asset_criticality']); ?>
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <?php if (!empty($vuln['cve_id'])): ?>
                                                            <a href="https://nvd.nist.gov/vuln/detail/<?php echo htmlspecialchars($vuln['cve_id']); ?>" target="_blank" class="text-decoration-none">
                                                                <?php echo htmlspecialchars($vuln['cve_id']); ?> <i class="fas fa-external-link-alt fa-xs"></i>
                                                            </a>
                                                        <?php else: ?>
                                                            <span class="text-muted">N/A</span>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td>
                                                        <span class="badge <?php 
                                                            switch ($vuln['status']) {
                                                                case 'open': echo 'bg-danger'; break;
                                                                case 'in_progress': echo 'bg-warning text-dark'; break;
                                                                case 'mitigated': echo 'bg-primary'; break;
                                                                case 'resolved': echo 'bg-success'; break;
                                                                case 'accepted_risk': echo 'bg-secondary'; break;
                                                                default: echo 'bg-info';
                                                            }
                                                        ?>">
                                                            <?php echo ucfirst(str_replace('_', ' ', $vuln['status'])); ?>
                                                        </span>
                                                        <?php if ($vuln['status'] === 'resolved' && !empty($vuln['resolved_at'])): ?>
                                                            <div class="small text-muted">
                                                                <?php echo date('Y-m-d', strtotime($vuln['resolved_at'])); ?>
                                                            </div>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td>
                                                        <div><?php echo date('Y-m-d', strtotime($vuln['discovered_at'])); ?></div>
                                                        <small class="text-muted"><?php echo date('H:i:s', strtotime($vuln['discovered_at'])); ?></small>
                                                    </td>
                                                    <td>
                                                        <div class="dropdown">
                                                            <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" id="actionDropdown<?php echo $vuln['vuln_id']; ?>" data-bs-toggle="dropdown" aria-expanded="false">
                                                                <i class="fas fa-ellipsis-v"></i>
                                                            </button>
                                                            <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="actionDropdown<?php echo $vuln['vuln_id']; ?>">
                                                                <li><a class="dropdown-item view-vulnerability" href="#" data-bs-toggle="modal" data-bs-target="#viewVulnerabilityModal" data-vuln-id="<?php echo $vuln['vuln_id']; ?>"><i class="fas fa-eye"></i> View Details</a></li>
                                                                
                                                                <?php if (hasRole('admin', 'manager', 'analyst')): ?>
                                                                    <li><a class="dropdown-item" href="#" data-bs-toggle="modal" data-bs-target="#editVulnerabilityModal" data-vuln-id="<?php echo $vuln['vuln_id']; ?>"><i class="fas fa-edit"></i> Edit</a></li>
                                                                    
                                                                    <li><hr class="dropdown-divider"></li>
                                                                    
                                                                    <?php if ($vuln['status'] === 'open'): ?>
                                                                        <li><a class="dropdown-item update-status" href="#" data-vuln-id="<?php echo $vuln['vuln_id']; ?>" data-status="in_progress"><i class="fas fa-hourglass-start"></i> Mark as In Progress</a></li>
                                                                    <?php endif; ?>
                                                                    
                                                                    <?php if ($vuln['status'] === 'open' || $vuln['status'] === 'in_progress'): ?>
                                                                        <li><a class="dropdown-item update-status" href="#" data-vuln-id="<?php echo $vuln['vuln_id']; ?>" data-status="mitigated"><i class="fas fa-shield-alt"></i> Mark as Mitigated</a></li>
                                                                    <?php endif; ?>
                                                                    
                                                                    <?php if ($vuln['status'] !== 'resolved' && $vuln['status'] !== 'accepted_risk'): ?>
                                                                        <li><a class="dropdown-item" href="#" data-bs-toggle="modal" data-bs-target="#resolveVulnerabilityModal" data-vuln-id="<?php echo $vuln['vuln_id']; ?>"><i class="fas fa-check-circle"></i> Mark as Resolved</a></li>
                                                                        <li><a class="dropdown-item" href="#" data-bs-toggle="modal" data-bs-target="#acceptRiskModal" data-vuln-id="<?php echo $vuln['vuln_id']; ?>"><i class="fas fa-exclamation-triangle"></i> Accept Risk</a></li>
                                                                    <?php endif; ?>
                                                                <?php endif; ?>
                                                            </ul>
                                                        </div>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        <?php endif; ?>
                                    </tbody>
                                </table>
                            </div>
                            
                            <!-- Bulk update note modal -->
                            <div class="modal fade" id="bulkUpdateModal" tabindex="-1" aria-labelledby="bulkUpdateModalLabel" aria-hidden="true">
                                <div class="modal-dialog">
                                    <div class="modal-content">
                                        <div class="modal-header">
                                            <h5 class="modal-title" id="bulkUpdateModalLabel">Update Vulnerability Status</h5>
                                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                        </div>
                                        <div class="modal-body">
                                            <input type="hidden" name="bulk_action" id="bulkActionField" value="">
                                            
                                            <div class="mb-3">
                                                <label for="bulk_status_note" class="form-label">Status Change Note</label>
                                                <textarea class="form-control" id="bulk_status_note" name="bulk_status_note" rows="3" placeholder="Provide a note about this status change"></textarea>
                                            </div>
                                        </div>
                                        <div class="modal-footer">
                                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                            <button type="submit" class="btn btn-primary">Update Status</button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </form>
                        
                        <!-- Pagination -->
                        <?php if ($totalPages > 1): ?>
                            <div class="d-flex justify-content-between align-items-center p-3">
                                <div>
                                    Showing <?php echo $offset + 1; ?> to <?php echo min($offset + $limit, $totalRows); ?> of <?php echo $totalRows; ?> vulnerabilities
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
    
    <!-- Add Vulnerability Modal -->
    <div class="modal fade" id="addVulnerabilityModal" tabindex="-1" aria-labelledby="addVulnerabilityModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" name="action" value="add_vulnerability">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="addVulnerabilityModalLabel">Add New Vulnerability</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="vuln_name" class="form-label">Vulnerability Name <span class="text-danger">*</span></label>
                                <input type="text" class="form-control" id="vuln_name" name="vuln_name" required>
                            </div>
                            <div class="col-md-6">
                                <label for="cve_id" class="form-label">CVE ID</label>
                                <input type="text" class="form-control" id="cve_id" name="cve_id" placeholder="e.g. CVE-2021-44228">
                            </div>
                        </div>
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="asset_id" class="form-label">Affected Asset <span class="text-danger">*</span></label>
                                <select class="form-select" id="asset_id" name="asset_id" required>
                                    <option value="">-- Select Asset --</option>
                                    <?php foreach ($assets as $id => $name): ?>
                                        <option value="<?php echo $id; ?>" <?php echo $filterAssetId === $id ? 'selected' : ''; ?>>
                                            <?php echo htmlspecialchars($name); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="col-md-6">
                                <label for="severity" class="form-label">Severity <span class="text-danger">*</span></label>
                                <select class="form-select" id="severity" name="severity" required>
                                    <option value="">-- Select Severity --</option>
                                    <option value="critical">Critical</option>
                                    <option value="high">High</option>
                                    <option value="medium">Medium</option>
                                    <option value="low">Low</option>
                                    <option value="informational">Informational</option>
                                </select>
                            </div>
                        </div>
                        <div class="mb-3">
                            <label for="description" class="form-label">Description <span class="text-danger">*</span></label>
                            <textarea class="form-control" id="description" name="description" rows="3" required></textarea>
                        </div>
                        <div class="mb-3">
                            <label for="remediation" class="form-label">Remediation Steps</label>
                            <textarea class="form-control" id="remediation" name="remediation" rows="3"></textarea>
                        </div>
                        <div class="mb-3">
                            <label for="discovered_at" class="form-label">Discovery Date <span class="text-danger">*</span></label>
                            <input type="text" class="form-control datepicker" id="discovered_at" name="discovered_at" value="<?php echo date('Y-m-d'); ?>" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Vulnerability</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- View Vulnerability Modal -->
    <div class="modal fade" id="viewVulnerabilityModal" tabindex="-1" aria-labelledby="viewVulnerabilityModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="viewVulnerabilityModalLabel">Vulnerability Details</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div id="vulnerabilityDetailsContent">
                        <div class="text-center">
                            <div class="spinner-border text-primary" role="status">
                                <span class="visually-hidden">Loading...</span>
                            </div>
                            <p class="mt-2">Loading vulnerability details...</p>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    <?php if (hasRole('admin', 'manager', 'analyst')): ?>
                    <a href="#" class="btn btn-primary" id="editVulnBtn">Edit</a>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Edit Vulnerability Modal -->
    <div class="modal fade" id="editVulnerabilityModal" tabindex="-1" aria-labelledby="editVulnerabilityModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" name="action" value="update_vulnerability">
                    <input type="hidden" name="vuln_id" id="edit_vuln_id" value="">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="editVulnerabilityModalLabel">Edit Vulnerability</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="edit_vuln_name" class="form-label">Vulnerability Name <span class="text-danger">*</span></label>
                                <input type="text" class="form-control" id="edit_vuln_name" name="vuln_name" required>
                            </div>
                            <div class="col-md-6">
                                <label for="edit_cve_id" class="form-label">CVE ID</label>
                                <input type="text" class="form-control" id="edit_cve_id" name="cve_id" placeholder="e.g. CVE-2021-44228">
                            </div>
                        </div>
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="edit_asset_id" class="form-label">Affected Asset <span class="text-danger">*</span></label>
                                <select class="form-select" id="edit_asset_id" name="asset_id" disabled>
                                    <?php foreach ($assets as $id => $name): ?>
                                        <option value="<?php echo $id; ?>">
                                            <?php echo htmlspecialchars($name); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                                <div class="form-text">Asset cannot be changed after creation.</div>
                            </div>
                            <div class="col-md-6">
                                <label for="edit_severity" class="form-label">Severity <span class="text-danger">*</span></label>
                                <select class="form-select" id="edit_severity" name="severity" required>
                                    <option value="critical">Critical</option>
                                    <option value="high">High</option>
                                    <option value="medium">Medium</option>
                                    <option value="low">Low</option>
                                    <option value="informational">Informational</option>
                                </select>
                            </div>
                        </div>
                        <div class="mb-3">
                            <label for="edit_description" class="form-label">Description <span class="text-danger">*</span></label>
                            <textarea class="form-control" id="edit_description" name="description" rows="3" required></textarea>
                        </div>
                        <div class="mb-3">
                            <label for="edit_remediation" class="form-label">Remediation Steps</label>
                            <textarea class="form-control" id="edit_remediation" name="remediation" rows="3"></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Update Vulnerability</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Resolve Vulnerability Modal -->
    <div class="modal fade" id="resolveVulnerabilityModal" tabindex="-1" aria-labelledby="resolveVulnerabilityModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" name="action" value="update_status">
                    <input type="hidden" name="vuln_id" id="resolve_vuln_id" value="">
                    <input type="hidden" name="new_status" value="resolved">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="resolveVulnerabilityModalLabel">Mark Vulnerability as Resolved</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <p>Are you sure you want to mark this vulnerability as resolved?</p>
                        
                        <div class="mb-3">
                            <label for="status_note" class="form-label">Resolution Notes</label>
                            <textarea class="form-control" id="status_note" name="status_note" rows="3" placeholder="Describe how this vulnerability was resolved"></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-success">Mark as Resolved</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Accept Risk Modal -->
    <div class="modal fade" id="acceptRiskModal" tabindex="-1" aria-labelledby="acceptRiskModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" name="action" value="update_status">
                    <input type="hidden" name="vuln_id" id="risk_vuln_id" value="">
                    <input type="hidden" name="new_status" value="accepted_risk">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="acceptRiskModalLabel">Accept Risk for Vulnerability</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="alert alert-warning">
                            <i class="fas fa-exclamation-triangle"></i> By accepting risk, you are acknowledging that this vulnerability will not be remediated.
                        </div>
                        
                        <div class="mb-3">
                            <label for="risk_status_note" class="form-label">Risk Acceptance Justification <span class="text-danger">*</span></label>
                            <textarea class="form-control" id="risk_status_note" name="status_note" rows="3" placeholder="Provide detailed justification for accepting this risk" required></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-warning">Accept Risk</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Update Status Form (Hidden) -->
    <form id="updateStatusForm" method="post" style="display: none;">
        <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
        <input type="hidden" name="action" value="update_status">
        <input type="hidden" name="vuln_id" id="status_vuln_id" value="">
        <input type="hidden" name="new_status" id="new_status" value="">
        <input type="hidden" name="status_note" value="Status updated via quick action">
    </form>
    
    <!-- Export Modal -->
    <div class="modal fade" id="exportModal" tabindex="-1" aria-labelledby="exportModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <form action="export-vulnerabilities.php" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    
                    <div class="modal-header">
                        <h5 class="modal-title" id="exportModalLabel">Export Vulnerabilities</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class            // If status is resolved or accepted_risk, set resolved_at
            if ($newStatus === 'resolved' || $newStatus === 'accepted_risk') {
                $resolvedAt = date('Y-m-d H:i:s');
                $stmt = $conn->prepare("UPDATE vulnerabilities SET status = ?, resolved_at = ? WHERE vuln_id = ?");
                $stmt->bind_param("ssi", $newStatus, $resolvedAt, $vulnId);
            } else {
                $stmt = $conn->prepare("UPDATE vulnerabilities SET status = ?, resolved_at = NULL WHERE vuln_id = ?");
                $stmt->bind_param("si", $newStatus, $vulnId);
            }
            
            if ($stmt->execute()) {
                $message = "Vulnerability status updated successfully";
                $messageType = "success";
                
                // Get vulnerability name for logging
                $vulnName = "";
                $vulnAssetId = 0;
                $stmt2 = $conn->prepare("SELECT vuln_name, asset_id FROM vulnerabilities WHERE vuln_id = ?");
                $stmt2->bind_param("i", $vulnId);
                $stmt2->execute();
                $stmt2->bind_result($vulnName, $vulnAssetId);
                $stmt2->fetch();
                $stmt2->close();
                
                // Add status change to logs
                $stmt3 = $conn->prepare("INSERT INTO vulnerability_status_logs (vuln_id, previous_status, new_status, notes, changed_by, changed_at) 
                                       VALUES (?, (SELECT status FROM vulnerabilities WHERE vuln_id = ?), ?, ?, ?, NOW())");
                $stmt3->bind_param("iissi", $vulnId, $vulnId, $newStatus, $statusNote, $userId);
                $stmt3->execute();
                $stmt3->close();
                
                // Log the action
                logSecurityEvent('vulnerability', 'info', "Updated vulnerability status: $vulnName (ID: $vulnId) to $newStatus", $userId, getClientIP());
            } else {
                $message = "Error updating vulnerability status: " . $conn->error;
                $messageType = "danger";
            }
            $stmt->close();
        }
        
        // Update vulnerability details
        else if ($action === 'update_vulnerability' && hasRole('admin', 'manager', 'analyst')) {
            $vulnId = intval($_POST['vuln_id']);
            $vulnName = sanitizeInput($_POST['vuln_name']);
            $cveId = sanitizeInput($_POST['cve_id']);
            $severity = sanitizeInput($_POST['severity']);
            $description = sanitizeInput($_POST['description']);
            $remediation = sanitizeInput($_POST['remediation']);
            
            // Update vulnerability
            $stmt = $conn->prepare("UPDATE vulnerabilities SET vuln_name = ?, cve_id = ?, severity = ?, description = ?, remediation = ? WHERE vuln_id = ?");
            $stmt->bind_param("sssssi", $vulnName, $cveId, $severity, $description, $remediation, $vulnId);
            
            if ($stmt->execute()) {
                $message = "Vulnerability updated successfully";
                $messageType = "success";
                
                // Log the action
                logSecurityEvent('vulnerability', 'info', "Updated vulnerability details: $vulnName, ID: $vulnId", $userId, getClientIP());
            } else {
                $message = "Error updating vulnerability: " . $conn->error;
                $messageType = "danger";
            }
            $stmt->close();
        }
        
        // Bulk update vulnerabilities
        else if ($action === 'bulk_update' && isset($_POST['selected_vulnerabilities']) && hasRole('admin', 'manager', 'analyst')) {
            $selectedVulns = $_POST['selected_vulnerabilities'];
            $bulkAction = sanitizeInput($_POST['bulk_action']);
            $statusNote = sanitizeInput($_POST['bulk_status_note'] ?? '');
            
            // Make sure selected vulnerabilities is an array
            if (!is_array($selectedVulns)) {
                $selectedVulns = [$selectedVulns];
            }
            
            // Convert to integers to prevent SQL injection
            $selectedVulns = array_map('intval', $selectedVulns);
            $selectedVulnsStr = implode(',', $selectedVulns);
            
            if (!empty($selectedVulnsStr)) {
                $resolvedAt = date('Y-m-d H:i:s');
                $updatedCount = 0;
                
                // Begin transaction for bulk updates
                $conn->begin_transaction();
                
                try {
                    // Update vulnerabilities
                    if ($bulkAction === 'resolved' || $bulkAction === 'accepted_risk') {
                        $stmt = $conn->prepare("UPDATE vulnerabilities SET status = ?, resolved_at = ? WHERE vuln_id IN ($selectedVulnsStr)");
                        $stmt->bind_param("ss", $bulkAction, $resolvedAt);
                    } else {
                        $stmt = $conn->prepare("UPDATE vulnerabilities SET status = ?, resolved_at = NULL WHERE vuln_id IN ($selectedVulnsStr)");
                        $stmt->bind_param("s", $bulkAction);
                    }
                    
                    $stmt->execute();
                    $updatedCount = $stmt->affected_rows;
                    
                    // Add status change to logs for each vulnerability
                    foreach ($selectedVulns as $vulnId) {
                        $previousStatus = "";
                        $vulnName = "";
                        
                        // Get previous status and vuln name
                        $stmt2 = $conn->prepare("SELECT status, vuln_name FROM vulnerabilities WHERE vuln_id = ?");
                        $stmt2->bind_param("i", $vulnId);
                        $stmt2->execute();
                        $stmt2->bind_result($previousStatus, $vulnName);
                        $stmt2->fetch();
                        $stmt2->close();
                        
                        // Log status change
                        $stmt3 = $conn->prepare("INSERT INTO vulnerability_status_logs (vuln_id, previous_status, new_status, notes, changed_by, changed_at) 
                                              VALUES (?, ?, ?, ?, ?, NOW())");
                        $stmt3->bind_param("isssi", $vulnId, $previousStatus, $bulkAction, $statusNote, $userId);
                        $stmt3->execute();
                        $stmt3->close();
                        
                        // Log the action
                        logSecurityEvent('vulnerability', 'info', "Bulk updated vulnerability status: $vulnName (ID: $vulnId) to $bulkAction", $userId, getClientIP());
                    }
                    
                    // Commit transaction
                    $conn->commit();
                    
                    $message = "$updatedCount vulnerability(ies) updated successfully";
                    $messageType = "success";
                    
                } catch (Exception $e) {
                    // Rollback on error
                    $conn->rollback();
                    
                    $message = "Error performing bulk update: " . $e->getMessage();
                    $messageType = "danger";
                }
            } else {
                $message = "No vulnerabilities selected";
                $messageType = "warning";
            }
        }
    }
}

// Pagination parameters
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$limit = isset($_GET['limit']) ? intval($_GET['limit']) : 25;
$offset = ($page - 1) * $limit;

// Filtering parameters
$filterSeverity = isset($_GET['severity']) ? $_GET['severity'] : '';
$filterStatus = isset($_GET['status']) ? $_GET['status'] : '';
$filterAssetId = isset($_GET['asset_id']) ? intval($_GET['asset_id']) : 0;
$filterCveId = isset($_GET['cve_id']) ? $_GET['cve_id'] : '';
$filterDateFrom = isset($_GET['date_from']) ? $_GET['date_from'] : '';
$filterDateTo = isset($_GET['date_to']) ? $_GET['date_to'] : '';
$searchQuery = isset($_GET['search']) ? $_GET['search'] : '';

// Build the query
$query = "SELECT v.*, a.asset_name, a.ip_address, a.criticality as asset_criticality 
         FROM vulnerabilities v 
         LEFT JOIN assets a ON v.asset_id = a.asset_id 
         WHERE 1=1";

$countQuery = "SELECT COUNT(*) as total 
              FROM vulnerabilities v 
              LEFT JOIN assets a ON v.asset_id = a.asset_id 
              WHERE 1=1";

$params = [];
$types = "";

// Add filters to the query
if (!empty($filterSeverity)) {
    $query .= " AND v.severity = ?";
    $countQuery .= " AND v.severity = ?";
    $params[] = $filterSeverity;
    $types .= "s";
}

if (!empty($filterStatus)) {
    $query .= " AND v.status = ?";
    $countQuery .= " AND v.status = ?";
    $params[] = $filterStatus;
    $types .= "s";
}

if (!empty($filterAssetId)) {
    $query .= " AND v.asset_id = ?";
    $countQuery .= " AND v.asset_id = ?";
    $params[] = $filterAssetId;
    $types .= "i";
}

if (!empty($filterCveId)) {
    $query .= " AND v.cve_id = ?";
    $countQuery .= " AND v.cve_id = ?";
    $params[] = $filterCveId;
    $types .= "s";
}

if (!empty($filterDateFrom)) {
    $query .= " AND v.discovered_at >= ?";
    $countQuery .= " AND v.discovered_at >= ?";
    $params[] = $filterDateFrom . " 00:00:00";
    $types .= "s";
}

if (!empty($filterDateTo)) {
    $query .= " AND v.discovered_at <= ?";
    $countQuery .= " AND v.discovered_at <= ?";
    $params[] = $filterDateTo . " 23:59:59";
    $types .= "s";
}

if (!empty($searchQuery)) {
    $query .= " AND (v.vuln_name LIKE ? OR v.cve_id LIKE ? OR a.asset_name LIKE ? OR a.ip_address LIKE ?)";
    $countQuery .= " AND (v.vuln_name LIKE ? OR v.cve_id LIKE ? OR a.asset_name LIKE ? OR a.ip_address LIKE ?)";
    $searchParam = "%" . $searchQuery . "%";
    $params[] = $searchParam;
    $params[] = $searchParam;
    $params[] = $searchParam;
    $params[] = $searchParam;
    $types .= "ssss";
}

// Add sorting and pagination
$query .= " ORDER BY FIELD(v.severity, 'critical', 'high', 'medium', 'low', 'informational'), 
           FIELD(v.status, 'open', 'in_progress', 'mitigated', 'resolved', 'accepted_risk'),
           v.discovered_at DESC LIMIT ? OFFSET ?";
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

// Get vulnerabilities
$stmt = $conn->prepare($query);
if (!empty($types)) {
    $stmt->bind_param($types, ...$params);
}
$stmt->execute();
$result = $stmt->get_result();
$vulnerabilities = [];
while ($row = $result->fetch_assoc()) {
    $vulnerabilities[] = $row;
}

// Get severity counts for filter
$severityCounts = [];
$query = "SELECT severity, COUNT(*) as count FROM vulnerabilities GROUP BY severity ORDER BY 
         FIELD(severity, 'critical', 'high', 'medium', 'low', 'informational')";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $severityCounts[$row['severity']] = $row['count'];
}

// Get status counts for filter
$statusCounts = [];
$query = "SELECT status, COUNT(*) as count FROM vulnerabilities GROUP BY status ORDER BY 
         FIELD(status, 'open', 'in_progress', 'mitigated', 'resolved', 'accepted_risk')";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $statusCounts[$row['status']] = $row['count'];
}

// Get assets for filter
$assets = [];
$query = "SELECT a.asset_id, a.asset_name, a.ip_address, COUNT(v.vuln_id) as vuln_count 
         FROM assets a 
         LEFT JOIN vulnerabilities v ON a.asset_id = v.asset_id 
         GROUP BY a.asset_id 
         ORDER BY vuln_count DESC, a.asset_name";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    $assets[$row['asset_id']] = $row['asset_name'] . ($row['ip_address'] ? " (" . $row['ip_address'] . ")" : "");
}

// Get asset details if filtering by asset
$assetDetails = null;
if (!empty($filterAssetId)) {
    $stmt = $conn->prepare("SELECT asset_id, asset_name, asset_type, ip_address, criticality FROM assets WHERE asset_id = ?");
    $stmt->bind_param("i", $filterAssetId);
    $stmt->execute();
    $assetResult = $stmt->get_result();
    if ($assetResult->num_rows > 0) {
        $assetDetails = $assetResult->fetch_assoc();
    }
    $stmt->close();
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
    <title>Vulnerabilities - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="assets/css/style.css">
    <!-- Include modern UI framework CSS (Bootstrap, etc.) -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Include Font Awesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- Include Flatpickr for date pickers -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
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
                        <?php if ($assetDetails): ?>
                            <li class="breadcrumb-item"><a href="assets.php">Assets</a></li>
                            <li class="breadcrumb-item"><a href="assets.php?asset_id=<?php echo $assetDetails['asset_id']; ?>"><?php echo htmlspecialchars($assetDetails['asset_name']); ?></a></li>
                        <?php endif; ?>
                        <li class="breadcrumb-item active" aria-current="page">Vulnerabilities</li>
                    </ol>
                </nav>

                <?php if (isset($message)): ?>
                    <div class="alert alert-<?php echo $messageType; ?> alert-dismissible fade show" role="alert">
                        <?php echo $message; ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                <?php endif; ?>
                
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">
                        <i class="fas fa-bug"></i> 
                        <?php if ($assetDetails): ?>
                            Vulnerabilities for <?php echo htmlspecialchars($assetDetails['asset_name']); ?>
                        <?php else: ?>
                            Vulnerabilities
                        <?php endif; ?>
                    </h1>
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
                        <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#addVulnerabilityModal">
                            <i class="fas fa-plus"></i> Add Vulnerability
                        </button>
                        <?php endif; ?>
                    </div>
                </div>
                
                <!-- Vulnerability Stats -->
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="card bg-danger text-white h-100">
                            <div class="card-body py-3">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="card-title mb-0">Critical</h6>
                                        <h2 class="mt-2 mb-0"><?php echo isset($severityCounts['critical']) ? $severityCounts['critical'] : 0; ?></h2>
                                    </div>
                                    <i class="fas fa-exclamation-triangle fa-2x"></i>
                                </div>
                            </div>
                            <div class="card-footer d-flex align-items-center justify-content-between">
                                <a href="?severity=critical" class="text-white text-decoration-none small">View details</a>
                                <i class="fas fa-arrow-circle-right text-white"></i>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-3">
                        <div class="card bg-warning text-dark h-100">
                            <div class="card-body py-3">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="card-title mb-0">High</h6>
                                        <h2 class="mt-2 mb-0"><?php echo isset($severityCounts['high']) ? $severityCounts['high'] : 0; ?></h2>
                                    </div>
                                    <i class="fas fa-exclamation-circle fa-2x"></i>
                                </div>
                            </div>
                            <div class="card-footer d-flex align-items-center justify-content-between">
                                <a href="?severity=high" class="text-dark text-decoration-none small">View details</a>
                                <i class="fas fa-arrow-circle-right text-dark"></i>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-3">
                        <div class="card bg-primary text-white h-100">
                            <div class="card-body py-3">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="card-title mb-0">Open Vulnerabilities</h6>
                                        <h2 class="mt-2 mb-0"><?php echo isset($statusCounts['open']) ? $statusCounts['open'] : 0; ?></h2>
                                    </div>
                                    <i class="fas fa-lock-open fa-2x"></i>
                                </div>
                            </div>
                            <div class="card-footer d-flex align-items-center justify-content-between">
                                <a href="?status=open" class="text-white text-decoration-none small">View details</a>
                                <i class="fas fa-arrow-circle-right text-white"></i>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-3">
                        <div class="card bg-success text-white h-100">
                            <div class="card-body py-3">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="card-title mb-0">Resolved</h6>
                                        <h2 class="mt-2 mb-0"><?php echo isset($statusCounts['resolved']) ? $statusCounts['resolved'] : 0; ?></h2>
                                    </div>
                                    <i class="fas fa-check-circle fa-2x"></i>
                                </div>
                            </div>
                            <div class="card-footer d-flex align-items-center justify-content-between">
                                <a href="?status=resolved" class="text-white text-decoration-none small">View details</a>
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
                            <form action="vulnerabilities.php" method="get" id="filterForm">
                                <div class="row g-3">
                                    <div class="col-md-3">
                                        <label for="severity" class="form-label">Severity</label>
                                        <select class="form-select" id="severity" name="severity">
                                            <option value="">All Severities</option>
                                            <option value="critical" <?php echo $filterSeverity === 'critical' ? 'selected' : ''; ?>>
                                                Critical (<?php echo isset($severityCounts['critical']) ? $severityCounts['critical'] : 0; ?>)
                                            </option>
                                            <option value="high" <?php echo $filterSeverity === 'high' ? 'selected' : ''; ?>>
                                                High (<?php echo isset($severityCounts['high']) ? $severityCounts['high'] : 0; ?>)
                                            </option>
                                            <option value="medium" <?php echo $filterSeverity === 'medium' ? 'selected' : ''; ?>>
                                                Medium (<?php echo isset($severityCounts['medium']) ? $severityCounts['medium'] : 0; ?>)
                                            </option>
                                            <option value="low" <?php echo $filterSeverity === 'low' ? 'selected' : ''; ?>>
                                                Low (<?php echo isset($severityCounts['low']) ? $severityCounts['low'] : 0; ?>)
                                            </option>
                                            <option value="informational" <?php echo $filterSeverity === 'informational' ? 'selected' : ''; ?>>
                                                Informational (<?php echo isset($severityCounts['informational']) ? $severityCounts['informational'] : 0; ?>)
                                            </option>
                                        </select>
                                    </div>
                                    <div class="col-md-3">
                                        <label for="status" class="form-label">Status</label>
                                        <select class="form-select" id="status" name="status">
                                            <option value="">All Statuses</option>
                                            <option value="open" <?php echo $filterStatus === 'open' ? 'selected' : ''; ?>>
                                                Open (<?php echo isset($statusCounts['open']) ? $statusCounts['open'] : 0; ?>)
                                            </option>
                                            <option value="in_progress" <?php echo $filterStatus === 'in_progress' ? 'selected' : ''; ?>>
                                                In Progress (<?php echo isset($statusCounts['in_progress']) ? $statusCounts['in_progress'] : 0; ?>)
                                            </option>
                                            <option value="mitigated" <?php echo $filterStatus === 'mitigated' ? 'selected' : ''; ?>>
                                                Mitigated (<?php echo isset($statusCounts['mitigated']) ? $statusCounts['mitigated'] : 0; ?>)
                                            </option>
                                            <option value="resolved" <?php echo $filterStatus === 'resolved' ? 'selected' : ''; ?>>
                                                Resolved (<?php echo isset($statusCounts['resolved']) ? $statusCounts['resolved'] : 0; ?>)
                                            </option>
                                            <option value="accepted_risk" <?php echo $filterStatus === 'accepted_risk' ? 'selected' : ''; ?>>
                                                Accepted Risk (<?php echo isset($statusCounts['accepted_risk']) ? $statusCounts['accepted_risk'] : 0; ?>)
                                            </option>
                                        </select>
                                    </div>
                                    <div class="col-md-3">
                                        <label for="asset_id" class="form-label">Asset</label>
                                        <select class="form-select" id="asset_id" name="asset_id">
                                            <option value="">All Assets</option>
                                            <?php foreach ($assets as $id => $name): ?>
                                                <option value="<?php echo $id; ?>" <?php echo $filterAssetId === $id ? 'selected' : ''; ?>>
                                                    <?php echo htmlspecialchars($name); ?>
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                    <div class="col-md-3">
                                        <label for="cve_id" class="form-label">CVE ID</label>
                                        <input type="text" class="form-control" id="cve_id" name="cve_id" placeholder="e.g. CVE-2021-44228" value="<?php echo htmlspecialchars($filterCveId); ?>">
                                    </div>
                                    <div class="col-md-3">
                                        <label for="date_from" class="form-label">Discovered From</label>
                                        <input type="text" class="form-control datepicker" id="date_from" name="date_from" placeholder="YYYY-MM-DD" value="<?php echo htmlspecialchars($filterDateFrom); ?>">
                                    </div>
                                    <div class="col-md-3">
                                        <label for="date_to" class="form-label">Discovered To</label>
                                        <input type="text" class="form-control datepicker" id="date_to" name="date_to" placeholder="YYYY-MM-DD" value="<?php echo htmlspecialchars($filterDateTo); ?>">
                                    </div>
                                    <div class="col-md-4">
                                        <label for="search" class="form-label">Search</label>
                                        <input type="text" class="form-control" id="search" name="search" placeholder="Search vulnerabilities..." value="<?php echo htmlspecialchars($searchQuery); ?>">
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
                                        <a href="vulnerabilities.php<?php echo $filterAssetId ? '?asset_id=' . $filterAssetId : ''; ?>" class="btn btn-outline-secondary">
                                            <i class="fas fa-undo"></i> Clear Filters
                                        </a>
                                    </div>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
                
                <!-- Vulnerabilities table -->
                <div class="card">
                    <div class="card-body p-0">
                        <form id="bulkActionForm" method="post">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                            <input type="hidden" name="action" value="bulk_update">
                            
                            <!-- Bulk action toolbar -->
                            <div class="border-bottom p-3">
                                <div class="d-flex flex-wrap align-items-center"><?php
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

// Process vulnerability actions
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        $message = "Invalid request";
        $messageType = "danger";
    } else {
        $action = $_POST['action'];
        $userId = $_SESSION['user_id'];
        
        // Add new vulnerability
        if ($action === 'add_vulnerability' && hasRole('admin', 'manager', 'analyst')) {
            $assetId = intval($_POST['asset_id']);
            $vulnName = sanitizeInput($_POST['vuln_name']);
            $cveId = sanitizeInput($_POST['cve_id']);
            $severity = sanitizeInput($_POST['severity']);
            $description = sanitizeInput($_POST['description']);
            $remediation = sanitizeInput($_POST['remediation']);
            $discoveredAt = sanitizeInput($_POST['discovered_at']);
            
            // Insert new vulnerability
            $stmt = $conn->prepare("INSERT INTO vulnerabilities (asset_id, vuln_name, cve_id, severity, description, remediation, status, discovered_at) 
                                  VALUES (?, ?, ?, ?, ?, ?, 'open', ?)");
            $stmt->bind_param("issssss", $assetId, $vulnName, $cveId, $severity, $description, $remediation, $discoveredAt);
            
            if ($stmt->execute()) {
                $vulnId = $conn->insert_id;
                $message = "Vulnerability added successfully";
                $messageType = "success";
                
                // Log the action
                logSecurityEvent('vulnerability', 'info', "Added new vulnerability: $vulnName, ID: $vulnId", $userId, getClientIP());
            } else {
                $message = "Error adding vulnerability: " . $conn->error;
                $messageType = "danger";
            }
            $stmt->close();
        }
        
        // Update vulnerability status
        else if ($action === 'update_status' && hasRole('admin', 'manager', 'analyst')) {
            $vulnId = intval($_POST['vuln_id']);
            $newStatus = sanitizeInput($_POST['new_status']);
            $statusNote = sanitizeInput($_POST['status_note']);
            $resolvedAt = null;
            
            // If status is resolved or accepted_risk, set resolved_at
            if ($newStatus ===