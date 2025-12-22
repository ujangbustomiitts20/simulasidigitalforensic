<?php
/**
 * Orders Page - PT. TechMart Indonesia
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

$conn = getDbConnection();
$orders = [];

// VULNERABILITY: SQL Injection via status filter
$status_filter = isset($_GET['status']) ? $_GET['status'] : '';

if ($conn) {
    if ($status_filter) {
        // VULNERABLE QUERY
        $query = "SELECT o.*, c.first_name, c.last_name, c.email, p.name as product_name 
                  FROM orders o 
                  JOIN customers c ON o.customer_id = c.id 
                  JOIN products p ON o.product_id = p.id 
                  WHERE o.status = '$status_filter' 
                  ORDER BY o.order_date DESC";
    } else {
        $query = "SELECT o.*, c.first_name, c.last_name, c.email, p.name as product_name 
                  FROM orders o 
                  JOIN customers c ON o.customer_id = c.id 
                  JOIN products p ON o.product_id = p.id 
                  ORDER BY o.order_date DESC 
                  LIMIT 50";
    }
    
    $result = $conn->query($query);
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $orders[] = $row;
        }
    }
    $conn->close();
}

function getStatusBadge($status) {
    $colors = [
        'pending' => '#ffc107',
        'processing' => '#17a2b8',
        'shipped' => '#6f42c1',
        'delivered' => '#28a745',
        'cancelled' => '#dc3545'
    ];
    $color = $colors[$status] ?? '#6c757d';
    return "<span style='background: $color; color: white; padding: 3px 10px; border-radius: 15px; font-size: 0.85rem;'>$status</span>";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Orders - PT. TechMart Indonesia</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .navbar { background: linear-gradient(135deg, #1e3c72, #2a5298); padding: 15px 30px; color: white; display: flex; justify-content: space-between; align-items: center; }
        .navbar h1 { font-size: 1.5rem; }
        .navbar a { color: white; text-decoration: none; margin-left: 20px; }
        .container { max-width: 1400px; margin: 30px auto; padding: 0 20px; }
        .card { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .card h2 { margin-bottom: 20px; color: #333; }
        .filters { margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; }
        .filters a { padding: 8px 15px; background: #e9ecef; color: #333; text-decoration: none; border-radius: 5px; }
        .filters a:hover, .filters a.active { background: #1e3c72; color: white; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: 600; }
        tr:hover { background: #f5f5f5; }
        .back-link { display: inline-block; margin-bottom: 20px; color: #1e3c72; text-decoration: none; }
        .stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 20px; }
        .stat-box { background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }
        .stat-box .label { font-size: 0.85rem; color: #666; }
        .stat-box .value { font-size: 1.5rem; font-weight: bold; color: #1e3c72; }
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
            <h2>📦 Orders Management</h2>
            
            <div class="filters">
                <a href="orders.php" class="<?php echo !$status_filter ? 'active' : ''; ?>">All</a>
                <a href="orders.php?status=pending" class="<?php echo $status_filter == 'pending' ? 'active' : ''; ?>">Pending</a>
                <a href="orders.php?status=processing" class="<?php echo $status_filter == 'processing' ? 'active' : ''; ?>">Processing</a>
                <a href="orders.php?status=shipped" class="<?php echo $status_filter == 'shipped' ? 'active' : ''; ?>">Shipped</a>
                <a href="orders.php?status=delivered" class="<?php echo $status_filter == 'delivered' ? 'active' : ''; ?>">Delivered</a>
                <a href="orders.php?status=cancelled" class="<?php echo $status_filter == 'cancelled' ? 'active' : ''; ?>">Cancelled</a>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th>Order ID</th>
                        <th>Customer</th>
                        <th>Product</th>
                        <th>Qty</th>
                        <th>Total</th>
                        <th>Status</th>
                        <th>Date</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($orders)): ?>
                        <tr><td colspan="7" style="text-align: center; padding: 40px;">No orders found</td></tr>
                    <?php else: ?>
                        <?php foreach ($orders as $order): ?>
                        <tr>
                            <td>#<?php echo htmlspecialchars($order['id']); ?></td>
                            <td><?php echo htmlspecialchars($order['first_name'] . ' ' . $order['last_name']); ?></td>
                            <td><?php echo htmlspecialchars($order['product_name']); ?></td>
                            <td><?php echo htmlspecialchars($order['quantity']); ?></td>
                            <td>Rp <?php echo number_format($order['total_price'], 0, ',', '.'); ?></td>
                            <td><?php echo getStatusBadge($order['status']); ?></td>
                            <td><?php echo date('d M Y', strtotime($order['order_date'])); ?></td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
