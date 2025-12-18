<?php
/**
 * PT. TechMart Indonesia - Vulnerable Web Application
 * FOR EDUCATIONAL PURPOSES ONLY
 */
session_start();
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PT. TechMart Indonesia - E-Commerce</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .card { background: white; border-radius: 12px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); overflow: hidden; }
        .header { background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .nav { background: #34495e; padding: 15px; display: flex; justify-content: center; gap: 20px; flex-wrap: wrap; }
        .nav a { color: white; text-decoration: none; padding: 10px 20px; border-radius: 5px; transition: background 0.3s; }
        .nav a:hover { background: rgba(255,255,255,0.1); }
        .content { padding: 30px; }
        .products { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-top: 20px; }
        .product { border: 1px solid #eee; border-radius: 8px; padding: 20px; text-align: center; transition: transform 0.3s, box-shadow 0.3s; }
        .product:hover { transform: translateY(-5px); box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
        .product-icon { font-size: 60px; margin-bottom: 15px; }
        .product h3 { color: #2c3e50; margin-bottom: 10px; }
        .product .price { color: #e74c3c; font-size: 1.3em; font-weight: bold; margin: 10px 0; }
        .btn { background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); color: white; padding: 12px 24px; border: none; border-radius: 5px; cursor: pointer; transition: transform 0.2s; }
        .btn:hover { transform: scale(1.05); }
        footer { text-align: center; padding: 20px; color: #666; border-top: 1px solid #eee; margin-top: 30px; }
        .alert { padding: 15px; border-radius: 5px; margin: 15px 0; }
        .alert-info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="header">
                <h1>🛒 PT. TechMart Indonesia</h1>
                <p>Solusi Belanja Online Terpercaya</p>
            </div>
            
            <div class="nav">
                <a href="index.php">🏠 Home</a>
                <a href="products.php">📦 Products</a>
                <a href="search.php">🔍 Search</a>
                <?php if(isset($_SESSION['user'])): ?>
                    <a href="dashboard.php">📊 Dashboard</a>
                    <a href="customers.php">👥 Customers</a>
                    <a href="logout.php">🚪 Logout (<?php echo htmlspecialchars($_SESSION['user']); ?>)</a>
                <?php else: ?>
                    <a href="login.php">🔐 Login</a>
                <?php endif; ?>
            </div>
            
            <div class="content">
                <h2>Welcome to TechMart!</h2>
                <p>Temukan produk elektronik berkualitas dengan harga terbaik.</p>
                
                <div class="alert alert-info">
                    <strong>🎉 Promo Spesial!</strong> Diskon hingga 50% untuk semua produk elektronik. Berlaku hingga akhir bulan!
                </div>
                
                <h3 style="margin-top: 30px;">Featured Products</h3>
                <div class="products">
                    <div class="product">
                        <div class="product-icon">📱</div>
                        <h3>Smartphone Pro X</h3>
                        <p>Flagship dengan layar 6.7"</p>
                        <div class="price">Rp 5.999.000</div>
                        <button class="btn">Add to Cart</button>
                    </div>
                    <div class="product">
                        <div class="product-icon">💻</div>
                        <h3>Laptop Ultra</h3>
                        <p>Intel i7, 16GB RAM</p>
                        <div class="price">Rp 12.999.000</div>
                        <button class="btn">Add to Cart</button>
                    </div>
                    <div class="product">
                        <div class="product-icon">🎧</div>
                        <h3>Wireless Headphone</h3>
                        <p>Noise Cancelling</p>
                        <div class="price">Rp 899.000</div>
                        <button class="btn">Add to Cart</button>
                    </div>
                    <div class="product">
                        <div class="product-icon">⌚</div>
                        <h3>Smart Watch</h3>
                        <p>Health & Fitness Tracker</p>
                        <div class="price">Rp 1.499.000</div>
                        <button class="btn">Add to Cart</button>
                    </div>
                </div>
            </div>
            
            <footer>
                <p>&copy; 2025 PT. TechMart Indonesia. All rights reserved.</p>
                <p style="font-size: 12px; color: #999; margin-top: 5px;">
                    ⚠️ This is a simulation environment for educational purposes only.
                </p>
            </footer>
        </div>
    </div>
</body>
</html>
