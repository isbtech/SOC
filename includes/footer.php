<footer class="footer mt-auto py-3 bg-light">
    <div class="container">
        <div class="d-flex justify-content-between">
            <span class="text-muted">© <?php echo date('Y'); ?> <?php echo SITE_NAME; ?> | Security Operations Center</span>
            <span class="text-muted">Version 1.0</span>
        </div>
    </div>
</footer>

<!-- Session timeout warning modal -->
<div class="modal fade" id="sessionTimeoutModal" tabindex="-1" aria-labelledby="sessionTimeoutModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="sessionTimeoutModalLabel"><i class="fas fa-exclamation-triangle text-warning"></i> Session Timeout Warning</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <p>Your session is about to expire due to inactivity. You will be logged out in <span id="sessionCountdown">60</span> seconds.</p>
                <p>Do you want to continue working?</p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal" id="logoutNow">Logout Now</button>
                <button type="button" class="btn btn-primary" id="extendSession">Stay Logged In</button>
            </div>
        </div>
    </div>
</div>

<script>
    // Session timeout handling
    (function() {
        // Session timeout configuration (in milliseconds)
        const sessionTimeout = <?php echo SESSION_LIFETIME * 1000; ?>; // Convert seconds to milliseconds
        const warningTime = 60000; // Show warning 1 minute before timeout
        
        let sessionTimeoutTimer;
        let warningTimer;
        let countdownInterval;
        let secondsLeft = 60;
        
        function resetSessionTimers() {
            clearTimeout(sessionTimeoutTimer);
            clearTimeout(warningTimer);
            clearInterval(countdownInterval);
            
            // Set timeout to show warning
            warningTimer = setTimeout(function() {
                showWarning();
            }, sessionTimeout - warningTime);
            
            // Set timeout for session expiration
            sessionTimeoutTimer = setTimeout(function() {
                window.location.href = 'logout.php';
            }, sessionTimeout);
        }
        
        function showWarning() {
            secondsLeft = 60;
            updateCountdown();
            
            // Show the modal
            const sessionTimeoutModal = new bootstrap.Modal(document.getElementById('sessionTimeoutModal'));
            sessionTimeoutModal.show();
            
            // Start countdown
            countdownInterval = setInterval(updateCountdown, 1000);
        }
        
        function updateCountdown() {
            document.getElementById('sessionCountdown').textContent = secondsLeft;
            secondsLeft--;
            
            if (secondsLeft < 0) {
                clearInterval(countdownInterval);
                window.location.href = 'logout.php';
            }
        }
        
        function extendSession() {
            // Make AJAX request to extend session
            fetch('extend-session.php')
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        resetSessionTimers();
                        const sessionTimeoutModal = bootstrap.Modal.getInstance(document.getElementById('sessionTimeoutModal'));
                        sessionTimeoutModal.hide();
                    } else {
                        // Session could not be extended, redirect to login
                        window.location.href = 'logout.php';
                    }
                })
                .catch(error => {
                    console.error('Error extending session:', error);
                    window.location.href = 'logout.php';
                });
        }
        
        // Initialize timers when page loads
        resetSessionTimers();
        
        // Monitor user activity to reset timers
        const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];
        events.forEach(function(event) {
            document.addEventListener(event, resetSessionTimers, false);
        });
        
        // Setup button event handlers
        document.getElementById('extendSession').addEventListener('click', extendSession);
        document.getElementById('logoutNow').addEventListener('click', function() {
            window.location.href = 'logout.php';
        });
    })();
</script>
