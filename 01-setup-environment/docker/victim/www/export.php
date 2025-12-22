<?php
/**
 * Export Page - VULNERABLE TO DATA EXFILTRATION
 * PT. TechMart Indonesia
 * FOR EDUCATIONAL PURPOSES ONLY
 */
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}

// Database connection
function getDbConnection() {
    $host = getenv('MYSQL_HOST') ?: 'victim-db';
    $user = getenv('MYSQL_USER') ?: 'techmart_user';
    $pass = getenv('MYSQL_PASSWORD') ?: 'password123';
    $db = getenv('MYSQL_DATABASE') ?: 'techmart_db';
    
    $conn = @new mysqli($host, $user, $pass, $db);
    if ($conn->connect_error) {
        return null;
    }
    return $conn;
}

// Log untuk forensik
$log_time = date('Y-m-d H:i:s');
$log_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

// Handle export request
if (isset($_GET['type'])) {
    $conn = getDbConnection();
    if (!$conn) {
        die("Database connection failed");
    }
    
    $type = $_GET['type'];
    
    error_log("[$log_time] DATA EXPORT | IP: $log_ip | User: {$_SESSION['user']} | Type: $type");
    
    // VULNERABILITY: No rate limiting, no access control for sensitive data
    switch ($type) {
        case 'customers':
            // Export ALL customer data including sensitive info!
            $query = "SELECT id, first_name, last_name, email, phone, address, city, postal_code, credit_card, cvv, card_expiry, created_at FROM customers";
            $filename = "customers_export_" . date('Ymd_His') . ".csv";
            break;
            
        case 'orders':
            $query = "SELECT o.id, c.first_name, c.last_name, c.email, p.name as product, o.quantity, o.total_price, o.status, o.order_date 
                      FROM orders o 
                      JOIN customers c ON o.customer_id = c.id 
                      JOIN products p ON o.product_id = p.id";
            $filename = "orders_export_" . date('Ymd_His') . ".csv";
            break;
            
        case 'products':
            $query = "SELECT * FROM products";
            $filename = "products_export_" . date('Ymd_His') . ".csv";
            break;
            
        case 'full':
            // CRITICAL: Export ALL data - customers with credit cards
            $query = "SELECT * FROM customers";
            $filename = "full_database_export_" . date('Ymd_His') . ".csv";
            
            error_log("[$log_time] CRITICAL EXPORT | IP: $log_ip | Full database export attempted!");
            break;
            
        default:
            header('Location: export.php');
            exit;
    }
    
    $result = $conn->query($query);
    
    if ($result) {
        // Log to audit table
        try {
            $conn->query("INSERT INTO audit_log (action, details, ip_address, user_agent) VALUES ('DATA_EXPORT', 'Type: $type, File: $filename', '$log_ip', '" . ($_SERVER['HTTP_USER_AGENT'] ?? '') . "')");
        } catch (Exception $e) {}
        
        // Output CSV
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        
        $output = fopen('php://output', 'w');
        
        // Header
        $fields = $result->fetch_fields();
        $headers = [];
        foreach ($fields as $field) {
            $headers[] = $field->name;
        }
        fputcsv($output, $headers);
        
        // Data rows
        while ($row = $result->fetch_assoc()) {
            fputcsv($output, $row);
        }
        
        fclose($output);
        $conn->close();
        exit;
    }
    
    $conn->close();
}

$conn = getDbConnection();
$stats = [
    'customers' => 0,
    'orders' => 0,
    'products' => 0
];

if ($conn) {
    $result = $conn->query("SELECT COUNT(*) as count FROM customers");
    if ($result) $stats['customers'] = $result->fetch_assoc()['count'];

    $result = $conn->query("SELECT COUNT(*) as count FROM orders");
    if ($result) $stats['orders'] = $result->fetch_assoc()['count'];

    $result = $conn->query("SELECT COUNT(*) as count FROM products");
    if ($result) $stats['products'] = $result->fetch_assoc()['count'];

    $conn->close();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Export Data - PT. TechMart Indonesia</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .navbar { background: linear-gradient(135deg, #1e3c72, #2a5298); padding: 15px 30px; color: white; display: flex; justify-content: space-between; align-items: center; }
        .navbar h1 { font-size: 1.5rem; }
        .navbar a { color: white; text-decoration: none; margin-left: 20px; }
        .container { max-width: 1000px; margin: 30px auto; padding: 0 20px; }
        .card { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .card h2 { margin-bottom: 20px; color: #333; }
        .warning { background: #fff3cd; padding: 15px; border-radius: 8px; margin-bottom: 20px; color: #856404; }
        .export-options { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; }
        .export-card { background: #f8f9fa; padding: 25px; border-radius: 10px; text-align: center; }
        .export-card .icon { font-size: 2.5rem; margin-bottom: 15px; }
        .export-card h3 { margin-bottom: 10px; color: #333; }
        .export-card p { color: #666; font-size: 0.9rem; margin-bottom: 15px; }
        .export-card .count { font-size: 1.5rem; font-weight: bold; color: #1e3c72; margin-bottom: 15px; }
        .export-btn { display: inline-block; padding: 10px 25px; background: #1e3c72; color: white; text-decoration: none; border-radius: 5px; }
        .export-btn:hover { background: #2a5298; }
        .export-btn.danger { background: #dc3545; }
        .export-btn.danger:hover { background: #c82333; }
        .back-link { display: inline-block; margin-bottom: 20px; color: #1e3c72; text-decoration: none; }
    </style>
</head>
<body>
    <nav class="navbar">
        <h1>🛒 PT. TechMart Indonesia</h1>
        <div>
            <span>Welcome, <?php echo htmlspecialchars($_SESSION['user']); ?></span>
            <a href="dashboard.php">Dashboard</a>
            <a href="logout.php">Logout</a>
        </div>
    </nav>
    
    <div class="container">
        <a href="dashboard.php" class="back-link">← Back to Dashboard</a>
        
        <div class="card">
            <h2>📊 Export Data</h2>
            
            <div class="warning">
                ⚠️ <strong>Warning:</strong> Exported data may contain sensitive information. Handle with care.
            </div>
            
            <div class="export-options">
                <div class="export-card">
                    <div class="icon">👥</div>
                    <h3>Customers</h3>
                    <p>Export all customer data including contact information</p>
                    <div class="count"><?php echo number_format($stats['customers']); ?> records</div>
                    <a href="export.php?type=customers" class="export-btn">📥 Export CSV</a>
                </div>
                
                <div class="export-card">
                    <div class="icon">📦</div>
                    <h3>Orders</h3>
                    <p>Export all order history with customer details</p>
                    <div class="count"><?php echo number_format($stats['orders']); ?> records</div>
                    <a href="export.php?type=orders" class="export-btn">📥 Export CSV</a>
                </div>
                
                <div class="export-card">
                    <div class="icon">🏷️</div>
                    <h3>Products</h3>
                    <p>Export product catalog with pricing</p>
                    <div class="count"><?php echo number_format($stats['products']); ?> records</div>
                    <a href="export.php?type=products" class="export-btn">📥 Export CSV</a>
                </div>
                
                <div class="export-card" style="border: 2px solid #dc3545;">
                    <div class="icon">⚠️</div>
                    <h3>Full Database</h3>
                    <p>Export ALL data including sensitive information (credit cards, etc.)</p>
                    <div class="count" style="color: #dc3545;">SENSITIVE</div>
                    <a href="export.php?type=full" class="export-btn danger">🔓 Export All</a>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
