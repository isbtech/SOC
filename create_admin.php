<?php
// Set password
$password = 'Admin@123';
$hashedPassword = password_hash($password, PASSWORD_BCRYPT);

// Connect to database
$conn = new mysqli("localhost", "cfsoccrimefire_socusrs", "41zJSTUxt6MHr1z", "cfsoccrimefire_socdbs");

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Check if admin exists
$result = $conn->query("SELECT * FROM users WHERE username = 'admin'");

if ($result->num_rows > 0) {
    // Update existing admin
    $stmt = $conn->prepare("UPDATE users SET password = ? WHERE username = 'admin'");
    $stmt->bind_param("s", $hashedPassword);
    $stmt->execute();
    echo "Admin password updated successfully. New hash: " . $hashedPassword;
} else {
    // Create new admin
    $stmt = $conn->prepare("INSERT INTO users (username, email, password, first_name, last_name, role) 
                           VALUES ('admin', 'admin@soc.local', ?, 'Admin', 'User', 'admin')");
    $stmt->bind_param("s", $hashedPassword);
    $stmt->execute();
    echo "Admin user created successfully. Hash: " . $hashedPassword;
}

$conn->close();
?>