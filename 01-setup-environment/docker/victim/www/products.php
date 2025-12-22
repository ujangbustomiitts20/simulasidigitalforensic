<?php
/**
 * Products Page - PT. TechMart Indonesia
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
$products = [];

// VULNERABILITY: SQL Injection via category filter
$category = isset($_GET['category']) ? $_GET['category'] : '';
$search = isset($_GET['search']) ? $_GET['search'] : '';

if ($conn) {
    if ($search) {
        // VULNERABLE QUERY - search
        $query = "SELECT * FROM products WHERE name LIKE '%$search%' OR description LIKE '%$search%' ORDER BY name";
    } elseif ($category) {
        // VULNERABLE QUERY - category filter
        $query = "SELECT * FROM products WHERE category = '$category' ORDER BY name";
    } else {
        $query = "SELECT * FROM products ORDER BY category, name";
    }
    
    $result = $conn->query($query);
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $products[] = $row;
        }
    }
    
    // Get categories
    $categories = [];
    $cat_result = $conn->query("SELECT DISTINCT category FROM products");
    if ($cat_result) {
        while ($row = $cat_result->fetch_assoc()) {
            $categories[] = $row['category'];
        }
    }
    
    $conn->close();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Products - PT. TechMart Indonesia</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .navbar { background: linear-gradient(135deg, #1e3c72, #2a5298); padding: 15px 30px; color: white; display: flex; justify-content: space-between; align-items: center; }
        .navbar h1 { font-size: 1.5rem; }
        .navbar a { color: white; text-decoration: none; margin-left: 20px; }
        .container { max-width: 1400px; margin: 30px auto; padding: 0 20px; }
        .card { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .card h2 { margin-bottom: 20px; color: #333; }
        .top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 15px; }
        .filters { display: flex; gap: 10px; flex-wrap: wrap; }
        .filters a { padding: 8px 15px; background: #e9ecef; color: #333; text-decoration: none; border-radius: 5px; }
        .filters a:hover, .filters a.active { background: #1e3c72; color: white; }
        .search-form { display: flex; gap: 10px; }
        .search-form input { padding: 8px 15px; border: 1px solid #ddd; border-radius: 5px; width: 200px; }
        .search-form button { padding: 8px 20px; background: #1e3c72; color: white; border: none; border-radius: 5px; cursor: pointer; }
        .products-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 20px; }
        .product-card { background: #f8f9fa; border-radius: 10px; padding: 20px; }
        .product-card h3 { color: #333; margin-bottom: 10px; }
        .product-card .category { font-size: 0.85rem; color: #666; background: #e9ecef; display: inline-block; padding: 3px 10px; border-radius: 15px; margin-bottom: 10px; }
        .product-card .description { color: #666; font-size: 0.9rem; margin-bottom: 15px; }
        .product-card .price { font-size: 1.3rem; font-weight: bold; color: #1e3c72; }
        .product-card .stock { font-size: 0.85rem; color: #28a745; margin-top: 5px; }
        .product-card .stock.low { color: #dc3545; }
        .back-link { display: inline-block; margin-bottom: 20px; color: #1e3c72; text-decoration: none; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: 600; }
        tr:hover { background: #f5f5f5; }
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
            <h2>🏷️ Products Catalog</h2>
            
            <div class="top-bar">
                <div class="filters">
                    <a href="products.php" class="<?php echo !$category ? 'active' : ''; ?>">All</a>
                    <?php foreach ($categories as $cat): ?>
                        <a href="products.php?category=<?php echo urlencode($cat); ?>" 
                           class="<?php echo $category == $cat ? 'active' : ''; ?>">
                            <?php echo htmlspecialchars($cat); ?>
                        </a>
                    <?php endforeach; ?>
                </div>
                
                <form class="search-form" method="GET">
                    <input type="text" name="search" placeholder="Search products..." 
                           value="<?php echo htmlspecialchars($search); ?>">
                    <button type="submit">🔍 Search</button>
                </form>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Product Name</th>
                        <th>Category</th>
                        <th>Price</th>
                        <th>Stock</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($products)): ?>
                        <tr><td colspan="6" style="text-align: center; padding: 40px;">No products found</td></tr>
                    <?php else: ?>
                        <?php foreach ($products as $product): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($product['id']); ?></td>
                            <td><strong><?php echo htmlspecialchars($product['name']); ?></strong></td>
                            <td>
                                <span style="background: #e9ecef; padding: 3px 10px; border-radius: 15px; font-size: 0.85rem;">
                                    <?php echo htmlspecialchars($product['category']); ?>
                                </span>
                            </td>
                            <td><strong>Rp <?php echo number_format($product['price'], 0, ',', '.'); ?></strong></td>
                            <td>
                                <span style="color: <?php echo $product['stock'] < 50 ? '#dc3545' : '#28a745'; ?>">
                                    <?php echo htmlspecialchars($product['stock']); ?> units
                                </span>
                            </td>
                            <td style="max-width: 300px; font-size: 0.9rem; color: #666;">
                                <?php echo htmlspecialchars($product['description']); ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
