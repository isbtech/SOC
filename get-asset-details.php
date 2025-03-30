<?php
/**
 * API endpoint for retrieving asset details
 */
require_once 'config.php';

// Initialize secure session
initSecureSession();

// Check if user is authenticated
if (!isAuthenticated()) {
    header('Content-Type: application/json');
    echo json_encode([
        'success' => false,
        'message' => 'Authentication required'
    ]);
    exit;
}

// Check if asset ID is provided
if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    header('Content-Type: application/json');
    echo json_encode([
        'success' => false,
        'message' => 'Invalid asset ID'
    ]);
    exit;
}

$assetId = (int)$_GET['id'];

// Connect to database
$conn = connectDB();

// Get asset details
$stmt = $conn->prepare("SELECT a.*, u.username as added_by_name 
                      FROM assets a 
                      LEFT JOIN users u ON a.added_by = u.user_id 
                      WHERE a.asset_id = ?");
$stmt->bind_param("i", $assetId);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    header('Content-Type: application/json');
    echo json_encode([
        'success' => false,
        'message' => 'Asset not found'
    ]);
    $conn->close();
    exit;
}

$asset = $result->fetch_assoc();

// Get vulnerability counts for this asset
$vulnCounts = [
    'total' => 0,
    'critical' => 0,
    'high' => 0,
    'medium' => 0,
    'low' => 0,
    'informational' => 0
];

$stmt = $conn->prepare("SELECT severity, COUNT(*) as count FROM vulnerabilities 
                       WHERE asset_id = ? AND status = 'open' 
                       GROUP BY severity");
$stmt->bind_param("i", $assetId);
$stmt->execute();
$vulnResult = $stmt->get_result();

while ($row = $vulnResult->fetch_assoc()) {
    $vulnCounts[$row['severity']] = $row['count'];
    $vulnCounts['total'] += $row['count'];
}

// Get open alerts for this asset
$recentAlerts = [];
$stmt = $conn->prepare("SELECT a.alert_id, a.alert_message, a.severity, a.status, a.created_at 
                       FROM alerts a 
                       JOIN security_events e ON a.event_id = e.event_id 
                       WHERE e.asset_id = ? 
                       ORDER BY a.created_at DESC 
                       LIMIT 5");
$stmt->bind_param("i", $assetId);
$stmt->execute();
$alertsResult = $stmt->get_result();

while ($row = $alertsResult->fetch_assoc()) {
    $recentAlerts[] = $row;
}

// Close the database connection
$conn->close();

// Return asset details as JSON
header('Content-Type: application/json');
echo json_encode([
    'success' => true,
    'asset' => $asset,
    'vulnerabilities' => $vulnCounts,
    'recent_alerts' => $recentAlerts
]);
exit;
