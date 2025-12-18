#!/bin/bash
#
# Setup Script untuk Victim Server (Web Application yang Rentan)
# Simulasi: PT. TechMart Indonesia E-Commerce Server
#

set -e

echo "=========================================="
echo "  SETUP VICTIM SERVER - PT. TechMart     "
echo "=========================================="

# Update system
apt-get update && apt-get upgrade -y

# Install dependencies
apt-get install -y \
    apache2 \
    mysql-server \
    php \
    php-mysql \
    php-curl \
    libapache2-mod-php \
    python3 \
    python3-pip \
    git \
    curl \
    wget \
    net-tools \
    auditd \
    rsyslog \
    tcpdump \
    ufw

# ============================================
# KONFIGURASI APACHE WEB SERVER
# ============================================
echo "[+] Configuring Apache Web Server..."

# Enable modules
a2enmod rewrite
a2enmod headers

# Create vulnerable web application directory
mkdir -p /var/www/techmart
chown -R www-data:www-data /var/www/techmart

# Configure virtual host
cat > /etc/apache2/sites-available/techmart.conf << 'EOF'
<VirtualHost *:80>
    ServerName techmart.local
    ServerAdmin webmaster@techmart.local
    DocumentRoot /var/www/techmart
    
    # Deliberately weak configuration for learning
    <Directory /var/www/techmart>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    # Enable logging for forensic analysis
    ErrorLog ${APACHE_LOG_DIR}/techmart-error.log
    CustomLog ${APACHE_LOG_DIR}/techmart-access.log combined
    
    # Log forensik tambahan
    CustomLog ${APACHE_LOG_DIR}/techmart-forensic.log "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %{X-Forwarded-For}i"
</VirtualHost>
EOF

a2ensite techmart.conf
a2dissite 000-default.conf

# ============================================
# KONFIGURASI MySQL DATABASE
# ============================================
echo "[+] Configuring MySQL Database..."

# Start MySQL
systemctl start mysql
systemctl enable mysql

# Create database and user (dengan password lemah untuk simulasi)
mysql -e "CREATE DATABASE IF NOT EXISTS techmart_db;"
mysql -e "CREATE USER IF NOT EXISTS 'techmart_user'@'localhost' IDENTIFIED BY 'password123';"
mysql -e "GRANT ALL PRIVILEGES ON techmart_db.* TO 'techmart_user'@'localhost';"
mysql -e "FLUSH PRIVILEGES;"

# Create tables with sample data
mysql techmart_db << 'EOF'
-- Table: users (admin dan customer)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role ENUM('admin', 'customer') DEFAULT 'customer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL
);

-- Table: customers (data pelanggan - target exfiltration)
CREATE TABLE IF NOT EXISTS customers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    email VARCHAR(100),
    phone VARCHAR(20),
    address TEXT,
    credit_card VARCHAR(20),
    cvv VARCHAR(4),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: orders
CREATE TABLE IF NOT EXISTS orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    customer_id INT,
    product_name VARCHAR(100),
    quantity INT,
    total_price DECIMAL(10,2),
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers(id)
);

-- Table: audit_log (untuk forensik)
CREATE TABLE IF NOT EXISTS audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    action VARCHAR(50),
    table_name VARCHAR(50),
    record_id INT,
    user_id INT,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details TEXT
);

-- Insert sample admin user (password: admin123 - deliberately weak)
INSERT INTO users (username, password, email, role) VALUES 
('admin', MD5('admin123'), 'admin@techmart.co.id', 'admin'),
('staff1', MD5('staff123'), 'staff1@techmart.co.id', 'customer');

-- Insert sample customer data (50 records untuk simulasi)
INSERT INTO customers (first_name, last_name, email, phone, address, credit_card, cvv) VALUES
('Budi', 'Santoso', 'budi.santoso@email.com', '081234567890', 'Jl. Sudirman No. 123, Jakarta', '4532015112830366', '123'),
('Siti', 'Rahayu', 'siti.rahayu@email.com', '081234567891', 'Jl. Gatot Subroto No. 45, Jakarta', '4539578763621486', '456'),
('Ahmad', 'Wijaya', 'ahmad.wijaya@email.com', '081234567892', 'Jl. Thamrin No. 67, Jakarta', '4916338506082832', '789'),
('Dewi', 'Kusuma', 'dewi.kusuma@email.com', '081234567893', 'Jl. Rasuna Said No. 89, Jakarta', '4024007198964305', '012'),
('Rizki', 'Pratama', 'rizki.pratama@email.com', '081234567894', 'Jl. Kuningan No. 12, Jakarta', '4556015886206505', '345'),
('Nurul', 'Hidayah', 'nurul.hidayah@email.com', '081234567895', 'Jl. Senayan No. 34, Jakarta', '4916171848395392', '678'),
('Fajar', 'Setiawan', 'fajar.setiawan@email.com', '081234567896', 'Jl. Kemang No. 56, Jakarta', '4539505652647935', '901'),
('Maya', 'Putri', 'maya.putri@email.com', '081234567897', 'Jl. Pondok Indah No. 78, Jakarta', '4916406379324655', '234'),
('Dimas', 'Nugroho', 'dimas.nugroho@email.com', '081234567898', 'Jl. Kelapa Gading No. 90, Jakarta', '4532148830861507', '567'),
('Rina', 'Wulandari', 'rina.wulandari@email.com', '081234567899', 'Jl. Sunter No. 11, Jakarta', '4916188225489628', '890');

-- Generate more dummy customers (total 50)
DELIMITER //
CREATE PROCEDURE IF NOT EXISTS generate_customers()
BEGIN
    DECLARE i INT DEFAULT 11;
    WHILE i <= 50 DO
        INSERT INTO customers (first_name, last_name, email, phone, address, credit_card, cvv)
        VALUES (
            CONCAT('Customer', i),
            CONCAT('LastName', i),
            CONCAT('customer', i, '@email.com'),
            CONCAT('08123456', LPAD(i, 4, '0')),
            CONCAT('Jl. Test No. ', i, ', Jakarta'),
            CONCAT('4', LPAD(FLOOR(RAND() * 999999999999999), 15, '0')),
            LPAD(FLOOR(RAND() * 1000), 3, '0')
        );
        SET i = i + 1;
    END WHILE;
END//
DELIMITER ;

CALL generate_customers();

EOF

# ============================================
# CREATE VULNERABLE WEB APPLICATION
# ============================================
echo "[+] Creating Vulnerable Web Application..."

# Index page
cat > /var/www/techmart/index.php << 'EOF'
<?php
session_start();
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PT. TechMart Indonesia - E-Commerce</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { background: #2c3e50; color: white; padding: 20px; text-align: center; margin: -20px -20px 20px; border-radius: 8px 8px 0 0; }
        .nav { background: #34495e; padding: 10px; margin: -20px -20px 20px; }
        .nav a { color: white; text-decoration: none; padding: 10px 20px; display: inline-block; }
        .nav a:hover { background: #2c3e50; }
        .product { border: 1px solid #ddd; padding: 15px; margin: 10px; display: inline-block; width: 200px; vertical-align: top; }
        .product img { width: 100%; height: 150px; object-fit: cover; background: #eee; }
        .btn { background: #3498db; color: white; padding: 10px 20px; border: none; cursor: pointer; border-radius: 4px; }
        .btn:hover { background: #2980b9; }
        .login-form { max-width: 400px; margin: 50px auto; }
        .login-form input { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }
        .alert { padding: 15px; margin: 10px 0; border-radius: 4px; }
        .alert-danger { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛒 PT. TechMart Indonesia</h1>
            <p>Solusi Belanja Online Terpercaya</p>
        </div>
        
        <div class="nav">
            <a href="index.php">Home</a>
            <a href="products.php">Products</a>
            <a href="search.php">Search</a>
            <?php if(isset($_SESSION['user'])): ?>
                <a href="dashboard.php">Dashboard</a>
                <a href="logout.php">Logout (<?php echo htmlspecialchars($_SESSION['user']); ?>)</a>
            <?php else: ?>
                <a href="login.php">Login</a>
            <?php endif; ?>
        </div>
        
        <h2>Welcome to TechMart!</h2>
        <p>Temukan produk elektronik berkualitas dengan harga terbaik.</p>
        
        <div class="products">
            <div class="product">
                <div style="background:#ddd;height:150px;display:flex;align-items:center;justify-content:center;">📱</div>
                <h3>Smartphone Pro X</h3>
                <p>Rp 5.999.000</p>
                <button class="btn">Add to Cart</button>
            </div>
            <div class="product">
                <div style="background:#ddd;height:150px;display:flex;align-items:center;justify-content:center;">💻</div>
                <h3>Laptop Ultra</h3>
                <p>Rp 12.999.000</p>
                <button class="btn">Add to Cart</button>
            </div>
            <div class="product">
                <div style="background:#ddd;height:150px;display:flex;align-items:center;justify-content:center;">🎧</div>
                <h3>Wireless Headphone</h3>
                <p>Rp 899.000</p>
                <button class="btn">Add to Cart</button>
            </div>
        </div>
        
        <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666;">
            <p>&copy; 2025 PT. TechMart Indonesia. All rights reserved.</p>
        </footer>
    </div>
</body>
</html>
EOF

# Login page (VULNERABLE to SQL Injection)
cat > /var/www/techmart/login.php << 'EOF'
<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $conn = new mysqli('localhost', 'techmart_user', 'password123', 'techmart_db');
    
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }
    
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // VULNERABLE: SQL Injection - Tidak ada sanitasi input!
    $query = "SELECT * FROM users WHERE username='$username' AND password=MD5('$password')";
    
    // Log query untuk forensik
    error_log("[LOGIN ATTEMPT] Query: $query | IP: " . $_SERVER['REMOTE_ADDR'] . " | Time: " . date('Y-m-d H:i:s'));
    
    $result = $conn->query($query);
    
    if ($result && $result->num_rows > 0) {
        $user = $result->fetch_assoc();
        $_SESSION['user'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        $_SESSION['user_id'] = $user['id'];
        
        // Update last login
        $conn->query("UPDATE users SET last_login=NOW() WHERE id=" . $user['id']);
        
        // Log successful login
        error_log("[LOGIN SUCCESS] User: " . $user['username'] . " | IP: " . $_SERVER['REMOTE_ADDR']);
        
        header('Location: dashboard.php');
        exit;
    } else {
        $error = "Invalid username or password!";
        // Log failed login
        error_log("[LOGIN FAILED] Username: $username | IP: " . $_SERVER['REMOTE_ADDR']);
    }
    
    $conn->close();
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>Login - TechMart</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h2 { text-align: center; color: #2c3e50; }
        input { width: 100%; padding: 12px; margin: 10px 0; box-sizing: border-box; border: 1px solid #ddd; border-radius: 4px; }
        .btn { background: #3498db; color: white; padding: 12px; border: none; cursor: pointer; border-radius: 4px; width: 100%; font-size: 16px; }
        .btn:hover { background: #2980b9; }
        .alert-danger { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 4px; margin: 10px 0; }
        a { color: #3498db; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔐 Login to TechMart</h2>
        
        <?php if($error): ?>
            <div class="alert-danger"><?php echo $error; ?></div>
        <?php endif; ?>
        
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" class="btn">Login</button>
        </form>
        
        <p style="text-align:center;margin-top:20px;">
            <a href="index.php">← Back to Home</a>
        </p>
        
        <!-- DEBUG INFO (untuk pembelajaran) -->
        <div style="margin-top:30px;padding:15px;background:#f0f0f0;border-radius:4px;font-size:12px;">
            <strong>🔧 Debug Info (For Learning):</strong><br>
            <code>Default Admin: admin / admin123</code>
        </div>
    </div>
</body>
</html>
EOF

# Dashboard page (VULNERABLE)
cat > /var/www/techmart/dashboard.php << 'EOF'
<?php
session_start();

if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}

$conn = new mysqli('localhost', 'techmart_user', 'password123', 'techmart_db');

// Get customer count
$result = $conn->query("SELECT COUNT(*) as total FROM customers");
$customer_count = $result->fetch_assoc()['total'];

// Get recent customers
$recent_customers = $conn->query("SELECT * FROM customers ORDER BY created_at DESC LIMIT 5");
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>Dashboard - TechMart Admin</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { background: #2c3e50; color: white; padding: 20px; margin: -20px -20px 20px; border-radius: 8px 8px 0 0; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat-box { background: #3498db; color: white; padding: 20px; border-radius: 8px; flex: 1; text-align: center; }
        .stat-box h3 { margin: 0; font-size: 36px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; }
        .nav { margin-bottom: 20px; }
        .nav a { color: #3498db; text-decoration: none; margin-right: 20px; }
        .btn { background: #3498db; color: white; padding: 8px 16px; border: none; cursor: pointer; border-radius: 4px; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Admin Dashboard</h1>
            <p>Welcome, <?php echo htmlspecialchars($_SESSION['user']); ?>!</p>
        </div>
        
        <div class="nav">
            <a href="index.php">🏠 Home</a>
            <a href="dashboard.php">📊 Dashboard</a>
            <a href="customers.php">👥 Customers</a>
            <a href="search_customers.php">🔍 Search</a>
            <a href="export.php">📥 Export Data</a>
            <a href="logout.php">🚪 Logout</a>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <h3><?php echo $customer_count; ?></h3>
                <p>Total Customers</p>
            </div>
            <div class="stat-box" style="background:#27ae60;">
                <h3>150</h3>
                <p>Orders Today</p>
            </div>
            <div class="stat-box" style="background:#e74c3c;">
                <h3>Rp 45.5M</h3>
                <p>Revenue</p>
            </div>
        </div>
        
        <h2>Recent Customers</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Phone</th>
                    <th>Created</th>
                </tr>
            </thead>
            <tbody>
                <?php while($row = $recent_customers->fetch_assoc()): ?>
                <tr>
                    <td><?php echo $row['id']; ?></td>
                    <td><?php echo htmlspecialchars($row['first_name'] . ' ' . $row['last_name']); ?></td>
                    <td><?php echo htmlspecialchars($row['email']); ?></td>
                    <td><?php echo htmlspecialchars($row['phone']); ?></td>
                    <td><?php echo $row['created_at']; ?></td>
                </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
    </div>
</body>
</html>
<?php $conn->close(); ?>
EOF

# Customers page (VULNERABLE - shows sensitive data)
cat > /var/www/techmart/customers.php << 'EOF'
<?php
session_start();

if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}

$conn = new mysqli('localhost', 'techmart_user', 'password123', 'techmart_db');

// VULNERABLE: No access control - semua user bisa lihat data pelanggan
$customers = $conn->query("SELECT * FROM customers ORDER BY id ASC");

// Log access
error_log("[DATA ACCESS] User: " . $_SESSION['user'] . " accessed customer list | IP: " . $_SERVER['REMOTE_ADDR']);
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>Customer Data - TechMart</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        table { width: 100%; border-collapse: collapse; font-size: 14px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #2c3e50; color: white; }
        tr:hover { background: #f5f5f5; }
        .sensitive { color: #e74c3c; font-family: monospace; }
        .nav a { color: #3498db; margin-right: 20px; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>👥 Customer Database</h1>
        
        <div class="nav" style="margin-bottom:20px;">
            <a href="dashboard.php">← Back to Dashboard</a>
            <a href="export.php">📥 Export to CSV</a>
        </div>
        
        <p>Total Records: <?php echo $customers->num_rows; ?></p>
        
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>First Name</th>
                    <th>Last Name</th>
                    <th>Email</th>
                    <th>Phone</th>
                    <th>Address</th>
                    <th>Credit Card</th>
                    <th>CVV</th>
                </tr>
            </thead>
            <tbody>
                <?php while($row = $customers->fetch_assoc()): ?>
                <tr>
                    <td><?php echo $row['id']; ?></td>
                    <td><?php echo htmlspecialchars($row['first_name']); ?></td>
                    <td><?php echo htmlspecialchars($row['last_name']); ?></td>
                    <td><?php echo htmlspecialchars($row['email']); ?></td>
                    <td><?php echo htmlspecialchars($row['phone']); ?></td>
                    <td><?php echo htmlspecialchars($row['address']); ?></td>
                    <td class="sensitive"><?php echo $row['credit_card']; ?></td>
                    <td class="sensitive"><?php echo $row['cvv']; ?></td>
                </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
    </div>
</body>
</html>
<?php $conn->close(); ?>
EOF

# Search page (VULNERABLE to SQL Injection)
cat > /var/www/techmart/search_customers.php << 'EOF'
<?php
session_start();

if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}

$conn = new mysqli('localhost', 'techmart_user', 'password123', 'techmart_db');
$results = null;
$search_term = '';

if (isset($_GET['q'])) {
    $search_term = $_GET['q'];
    
    // VULNERABLE: SQL Injection - tidak ada sanitasi!
    $query = "SELECT * FROM customers WHERE first_name LIKE '%$search_term%' OR last_name LIKE '%$search_term%' OR email LIKE '%$search_term%'";
    
    // Log query untuk forensik
    error_log("[SEARCH QUERY] Query: $query | User: " . $_SESSION['user'] . " | IP: " . $_SERVER['REMOTE_ADDR']);
    
    $results = $conn->query($query);
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>Search Customers - TechMart</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        input[type="text"] { padding: 12px; width: 400px; border: 1px solid #ddd; border-radius: 4px; }
        .btn { background: #3498db; color: white; padding: 12px 24px; border: none; cursor: pointer; border-radius: 4px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #2c3e50; color: white; }
        .nav a { color: #3498db; margin-right: 20px; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Search Customers</h1>
        
        <div class="nav" style="margin-bottom:20px;">
            <a href="dashboard.php">← Back to Dashboard</a>
        </div>
        
        <form method="GET">
            <input type="text" name="q" placeholder="Search by name or email..." value="<?php echo htmlspecialchars($search_term); ?>">
            <button type="submit" class="btn">Search</button>
        </form>
        
        <?php if($results): ?>
            <h3>Results for: "<?php echo htmlspecialchars($search_term); ?>"</h3>
            <p>Found: <?php echo $results->num_rows; ?> records</p>
            
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Email</th>
                        <th>Phone</th>
                        <th>Credit Card</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while($row = $results->fetch_assoc()): ?>
                    <tr>
                        <td><?php echo $row['id']; ?></td>
                        <td><?php echo htmlspecialchars($row['first_name'] . ' ' . $row['last_name']); ?></td>
                        <td><?php echo htmlspecialchars($row['email']); ?></td>
                        <td><?php echo htmlspecialchars($row['phone']); ?></td>
                        <td style="color:#e74c3c;font-family:monospace;"><?php echo $row['credit_card']; ?></td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        <?php endif; ?>
        
        <!-- Debug info untuk pembelajaran SQL Injection -->
        <div style="margin-top:30px;padding:15px;background:#fff3cd;border:1px solid #ffc107;border-radius:4px;">
            <strong>⚠️ Security Note (For Learning):</strong><br>
            <small>This search is vulnerable to SQL Injection. Try: <code>' OR '1'='1</code></small>
        </div>
    </div>
</body>
</html>
<?php $conn->close(); ?>
EOF

# Export page (VULNERABLE - allows data exfiltration)
cat > /var/www/techmart/export.php << 'EOF'
<?php
session_start();

if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}

$conn = new mysqli('localhost', 'techmart_user', 'password123', 'techmart_db');

// Log export activity (untuk forensik)
error_log("[DATA EXPORT] User: " . $_SESSION['user'] . " exported customer data | IP: " . $_SERVER['REMOTE_ADDR'] . " | Time: " . date('Y-m-d H:i:s'));

// Insert audit log
$user_id = $_SESSION['user_id'] ?? 0;
$ip = $_SERVER['REMOTE_ADDR'];
$conn->query("INSERT INTO audit_log (action, table_name, user_id, ip_address, details) VALUES ('EXPORT', 'customers', $user_id, '$ip', 'Full customer data export')");

// Export to CSV
header('Content-Type: text/csv');
header('Content-Disposition: attachment; filename="customers_export_' . date('Y-m-d_H-i-s') . '.csv"');

$output = fopen('php://output', 'w');

// Header
fputcsv($output, ['ID', 'First Name', 'Last Name', 'Email', 'Phone', 'Address', 'Credit Card', 'CVV', 'Created At']);

// Data
$result = $conn->query("SELECT * FROM customers");
while ($row = $result->fetch_assoc()) {
    fputcsv($output, $row);
}

fclose($output);
$conn->close();
exit;
?>
EOF

# Logout
cat > /var/www/techmart/logout.php << 'EOF'
<?php
session_start();
error_log("[LOGOUT] User: " . ($_SESSION['user'] ?? 'unknown') . " | IP: " . $_SERVER['REMOTE_ADDR']);
session_destroy();
header('Location: login.php');
exit;
?>
EOF

# Set permissions
chown -R www-data:www-data /var/www/techmart
chmod -R 755 /var/www/techmart

# ============================================
# KONFIGURASI LOGGING (untuk Forensik)
# ============================================
echo "[+] Configuring System Logging..."

# Configure rsyslog untuk enhanced logging
cat >> /etc/rsyslog.conf << 'EOF'

# Enhanced logging untuk forensik
*.* /var/log/forensic/all.log
auth,authpriv.* /var/log/forensic/auth.log
EOF

mkdir -p /var/log/forensic
chmod 750 /var/log/forensic

# Configure auditd
cat > /etc/audit/rules.d/forensic.rules << 'EOF'
# Audit rules untuk forensik

# Monitor file access di web directory
-w /var/www/techmart -p rwxa -k webfiles

# Monitor MySQL access
-w /var/lib/mysql -p rwxa -k database

# Monitor user authentication
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity

# Monitor sudoers
-w /etc/sudoers -p wa -k sudoers

# Monitor network configuration
-w /etc/network -p wa -k network

# Monitor cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron -p wa -k cron

# Monitor system calls untuk potential malicious activity
-a always,exit -F arch=b64 -S execve -k exec
EOF

systemctl restart auditd

# ============================================
# RESTART SERVICES
# ============================================
echo "[+] Restarting Services..."

systemctl restart apache2
systemctl restart mysql
systemctl restart rsyslog

# ============================================
# CREATE BACKDOOR LOCATION (untuk simulasi)
# ============================================
echo "[+] Creating hidden directory for backdoor simulation..."
mkdir -p /var/www/techmart/.hidden
chmod 755 /var/www/techmart/.hidden

# ============================================
# FINAL CONFIGURATION
# ============================================
echo "[+] Final Configuration..."

# Disable firewall untuk simulasi (JANGAN lakukan di production!)
ufw disable

# Create forensic user
useradd -m -s /bin/bash forensic 2>/dev/null || true
echo "forensic:forensic123" | chpasswd
usermod -aG sudo forensic

echo ""
echo "=========================================="
echo "  VICTIM SERVER SETUP COMPLETE!          "
echo "=========================================="
echo ""
echo "Web Application: http://192.168.56.10/"
echo "Admin Login: admin / admin123"
echo ""
echo "MySQL Database: techmart_db"
echo "MySQL User: techmart_user / password123"
echo ""
echo "Forensic User: forensic / forensic123"
echo ""
echo "Log Files:"
echo "  - /var/log/apache2/techmart-*.log"
echo "  - /var/log/forensic/"
echo "  - /var/log/audit/audit.log"
echo ""
echo "Vulnerabilities:"
echo "  - SQL Injection in login.php"
echo "  - SQL Injection in search_customers.php"
echo "  - No access control on sensitive data"
echo "  - Weak passwords"
echo "  - Data export without restrictions"
echo ""
