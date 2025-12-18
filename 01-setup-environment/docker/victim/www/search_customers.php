<?php
/**
 * Customer Search Page - VULNERABLE TO SQL INJECTION
 * PT. TechMart Indonesia
 * FOR EDUCATIONAL PURPOSES ONLY
 */
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

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

$results = [];
$search_query = '';
$error = '';
$debug_info = '';

if (isset($_GET['q']) && !empty($_GET['q'])) {
    $conn = getDbConnection();
    $search_query = $_GET['q'];
    
    // Log untuk forensik
    $log_time = date('Y-m-d H:i:s');
    $log_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    error_log("[$log_time] SEARCH | IP: $log_ip | Query: $search_query");
    
    if ($conn) {
        // =====================================================
        // VULNERABILITY: SQL INJECTION
        // Query tidak menggunakan prepared statements
        // Input tidak di-sanitasi
        // =====================================================
        $query = "SELECT id, first_name, last_name, email, phone, address FROM customers WHERE first_name LIKE '%$search_query%' OR last_name LIKE '%$search_query%' OR email LIKE '%$search_query%'";
        
        $debug_info = "Query: " . htmlspecialchars($query);
        
        // Log query untuk audit
        @$conn->query("INSERT INTO audit_log (action, details, ip_address, user_agent) VALUES ('SEARCH', '" . $conn->real_escape_string($query) . "', '$log_ip', '" . ($_SERVER['HTTP_USER_AGENT'] ?? '') . "')");
        
        $result = $conn->query($query);
    
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $results[] = $row;
            }
        } else {
            $error = "Database error: " . $conn->error;
            error_log("[$log_time] SEARCH ERROR | IP: $log_ip | Error: " . $conn->error);
        }
        
        $conn->close();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Search Customers - PT. TechMart Indonesia</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; min-height: 100vh; }
        .navbar { background: linear-gradient(135deg, #1e3c72, #2a5298); padding: 15px 30px; color: white; }
        .navbar h1 { font-size: 1.5rem; }
        .container { max-width: 1200px; margin: 30px auto; padding: 0 20px; }
        .search-box { background: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .search-box h2 { margin-bottom: 20px; color: #333; }
        .search-form { display: flex; gap: 10px; }
        .search-form input[type="text"] { flex: 1; padding: 12px 15px; border: 2px solid #ddd; border-radius: 5px; font-size: 1rem; }
        .search-form button { padding: 12px 30px; background: #1e3c72; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 1rem; }
        .search-form button:hover { background: #2a5298; }
        .results { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .results h3 { margin-bottom: 20px; color: #333; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: 600; }
        tr:hover { background: #f5f5f5; }
        .error { background: #fee; color: #c00; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .debug { background: #ffe; color: #880; padding: 15px; border-radius: 5px; margin-bottom: 20px; font-family: monospace; font-size: 0.85rem; }
        .no-results { text-align: center; padding: 40px; color: #666; }
        .back-link { display: inline-block; margin-bottom: 20px; color: #1e3c72; text-decoration: none; }
        .back-link:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <nav class="navbar">
        <h1>🛒 PT. TechMart Indonesia - Customer Search</h1>
    </nav>
    
    <div class="container">
        <a href="dashboard.php" class="back-link">← Back to Dashboard</a>
        
        <div class="search-box">
            <h2>🔍 Search Customers</h2>
            <form method="GET" class="search-form">
                <input type="text" name="q" placeholder="Search by name or email..." value="<?php echo htmlspecialchars($search_query); ?>">
                <button type="submit">Search</button>
            </form>
        </div>
        
        <?php if ($error): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <?php if ($debug_info && isset($_GET['debug'])): ?>
            <div class="debug"><?php echo $debug_info; ?></div>
        <?php endif; ?>
        
        <?php if ($search_query): ?>
            <div class="results">
                <h3>Search Results for "<?php echo htmlspecialchars($search_query); ?>" (<?php echo count($results); ?> found)</h3>
                
                <?php if (count($results) > 0): ?>
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>First Name</th>
                                <th>Last Name</th>
                                <th>Email</th>
                                <th>Phone</th>
                                <th>Address</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($results as $row): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($row['id'] ?? ''); ?></td>
                                    <td><?php echo htmlspecialchars($row['first_name'] ?? ''); ?></td>
                                    <td><?php echo htmlspecialchars($row['last_name'] ?? ''); ?></td>
                                    <td><?php echo htmlspecialchars($row['email'] ?? ''); ?></td>
                                    <td><?php echo htmlspecialchars($row['phone'] ?? ''); ?></td>
                                    <td><?php echo htmlspecialchars($row['address'] ?? ''); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php else: ?>
                    <div class="no-results">No customers found matching your search.</div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
