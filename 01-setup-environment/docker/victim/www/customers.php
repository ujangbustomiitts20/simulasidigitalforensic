<?php
/**
 * Customers Page - VULNERABLE TO SQL INJECTION
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

$conn = getDbConnection();
$customers = [];
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$limit = 20;
$offset = ($page - 1) * $limit;

// VULNERABILITY: SQL Injection possible via order parameter
$order = isset($_GET['order']) ? $_GET['order'] : 'id';
$dir = isset($_GET['dir']) ? $_GET['dir'] : 'ASC';

// Log untuk forensik
$log_time = date('Y-m-d H:i:s');
$log_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
error_log("[$log_time] CUSTOMERS VIEW | IP: $log_ip | Order: $order | Dir: $dir");

// VULNERABLE QUERY - order by injection possible
$query = "SELECT id, first_name, last_name, email, phone, address, created_at FROM customers ORDER BY $order $dir LIMIT $limit OFFSET $offset";

$total = 0;
$total_pages = 1;

if ($conn) {
    $result = $conn->query($query);
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $customers[] = $row;
        }
    }

    // Get total count
    $count_result = $conn->query("SELECT COUNT(*) as total FROM customers");
    $total = $count_result ? $count_result->fetch_assoc()['total'] : 0;
    $total_pages = ceil($total / $limit);

    $conn->close();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Customers - PT. TechMart Indonesia</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .navbar { background: linear-gradient(135deg, #1e3c72, #2a5298); padding: 15px 30px; color: white; display: flex; justify-content: space-between; align-items: center; }
        .navbar h1 { font-size: 1.5rem; }
        .navbar a { color: white; text-decoration: none; margin-left: 20px; }
        .container { max-width: 1400px; margin: 30px auto; padding: 0 20px; }
        .card { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .card h2 { margin-bottom: 20px; color: #333; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: 600; }
        th a { color: #1e3c72; text-decoration: none; }
        th a:hover { text-decoration: underline; }
        tr:hover { background: #f5f5f5; }
        .pagination { margin-top: 20px; text-align: center; }
        .pagination a { display: inline-block; padding: 8px 15px; margin: 0 5px; background: #1e3c72; color: white; text-decoration: none; border-radius: 5px; }
        .pagination a:hover { background: #2a5298; }
        .pagination span { padding: 8px 15px; background: #ddd; border-radius: 5px; }
        .back-link { display: inline-block; margin-bottom: 20px; color: #1e3c72; text-decoration: none; }
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
        <a href="dashboard.php" class="back-link">← Back to Dashboard</a>
        
        <div class="card">
            <h2>👥 Customer List (<?php echo number_format($total); ?> total)</h2>
            
            <table>
                <thead>
                    <tr>
                        <th><a href="?order=id&dir=<?php echo $dir == 'ASC' ? 'DESC' : 'ASC'; ?>">ID</a></th>
                        <th><a href="?order=first_name&dir=<?php echo $dir == 'ASC' ? 'DESC' : 'ASC'; ?>">First Name</a></th>
                        <th><a href="?order=last_name&dir=<?php echo $dir == 'ASC' ? 'DESC' : 'ASC'; ?>">Last Name</a></th>
                        <th><a href="?order=email&dir=<?php echo $dir == 'ASC' ? 'DESC' : 'ASC'; ?>">Email</a></th>
                        <th>Phone</th>
                        <th>Address</th>
                        <th>Created</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($customers as $c): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($c['id']); ?></td>
                            <td><?php echo htmlspecialchars($c['first_name']); ?></td>
                            <td><?php echo htmlspecialchars($c['last_name']); ?></td>
                            <td><?php echo htmlspecialchars($c['email']); ?></td>
                            <td><?php echo htmlspecialchars($c['phone']); ?></td>
                            <td><?php echo htmlspecialchars($c['address']); ?></td>
                            <td><?php echo htmlspecialchars($c['created_at']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            
            <?php if ($total_pages > 1): ?>
                <div class="pagination">
                    <?php if ($page > 1): ?>
                        <a href="?page=<?php echo $page - 1; ?>&order=<?php echo $order; ?>&dir=<?php echo $dir; ?>">« Prev</a>
                    <?php endif; ?>
                    
                    <span>Page <?php echo $page; ?> of <?php echo $total_pages; ?></span>
                    
                    <?php if ($page < $total_pages): ?>
                        <a href="?page=<?php echo $page + 1; ?>&order=<?php echo $order; ?>&dir=<?php echo $dir; ?>">Next »</a>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
