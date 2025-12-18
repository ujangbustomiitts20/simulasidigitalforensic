<?php
/**
 * Dashboard Page - PT. TechMart Indonesia
 * FOR EDUCATIONAL PURPOSES ONLY
 */
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Check if user is logged in
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

// Get statistics
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
    <title>Dashboard - PT. TechMart Indonesia</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .navbar { background: linear-gradient(135deg, #1e3c72, #2a5298); padding: 15px 30px; color: white; display: flex; justify-content: space-between; align-items: center; }
        .navbar h1 { font-size: 1.5rem; }
        .navbar a { color: white; text-decoration: none; margin-left: 20px; }
        .container { max-width: 1200px; margin: 30px auto; padding: 0 20px; }
        .welcome { background: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        .stat-card { background: white; padding: 30px; border-radius: 10px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stat-card h3 { color: #666; font-size: 1rem; margin-bottom: 10px; }
        .stat-card .number { font-size: 2.5rem; font-weight: bold; color: #1e3c72; }
        .menu { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 30px; }
        .menu-item { background: white; padding: 20px; border-radius: 10px; text-align: center; text-decoration: none; color: #333; box-shadow: 0 2px 10px rgba(0,0,0,0.1); transition: transform 0.3s; }
        .menu-item:hover { transform: translateY(-5px); }
        .menu-item .icon { font-size: 2rem; margin-bottom: 10px; }
    </style>
</head>
<body>
    <nav class="navbar">
        <h1>🛒 PT. TechMart Indonesia</h1>
        <div>
            <span>Welcome, <?php echo htmlspecialchars($_SESSION['user']); ?></span>
            <a href="logout.php">Logout</a>
        </div>
    </nav>
    
    <div class="container">
        <div class="welcome">
            <h2>Dashboard</h2>
            <p>Welcome back, <?php echo htmlspecialchars($_SESSION['user']); ?>! You are logged in as <?php echo htmlspecialchars($_SESSION['role'] ?? 'user'); ?>.</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Total Customers</h3>
                <div class="number"><?php echo number_format($stats['customers']); ?></div>
            </div>
            <div class="stat-card">
                <h3>Total Orders</h3>
                <div class="number"><?php echo number_format($stats['orders']); ?></div>
            </div>
            <div class="stat-card">
                <h3>Total Products</h3>
                <div class="number"><?php echo number_format($stats['products']); ?></div>
            </div>
        </div>
        
        <div class="menu">
            <a href="customers.php" class="menu-item">
                <div class="icon">👥</div>
                <div>Manage Customers</div>
            </a>
            <a href="orders.php" class="menu-item">
                <div class="icon">📦</div>
                <div>View Orders</div>
            </a>
            <a href="products.php" class="menu-item">
                <div class="icon">🏷️</div>
                <div>Products</div>
            </a>
            <a href="search_customers.php" class="menu-item">
                <div class="icon">🔍</div>
                <div>Search Customers</div>
            </a>
        </div>
    </div>
</body>
</html>
