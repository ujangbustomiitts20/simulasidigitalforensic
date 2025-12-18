<?php
/**
 * Login Page - VULNERABLE TO SQL INJECTION
 * PT. TechMart Indonesia
 * FOR EDUCATIONAL PURPOSES ONLY
 */
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

$error = '';
$debug_info = '';

// Database connection
function getDbConnection() {
    $host = getenv('MYSQL_HOST') ?: 'victim-db';
    $user = getenv('MYSQL_USER') ?: 'techmart_user';
    $pass = getenv('MYSQL_PASSWORD') ?: 'password123';
    $db = getenv('MYSQL_DATABASE') ?: 'techmart_db';
    
    // Try connection with retry
    $maxRetries = 3;
    $conn = null;
    
    for ($i = 0; $i < $maxRetries; $i++) {
        $conn = @new mysqli($host, $user, $pass, $db);
        if (!$conn->connect_error) {
            break;
        }
        sleep(1);
    }
    
    if ($conn->connect_error) {
        throw new Exception("Database connection failed: " . $conn->connect_error);
    }
    return $conn;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $conn = getDbConnection();
        
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        
        // =====================================================
        // VULNERABILITY: SQL INJECTION
        // Query tidak menggunakan prepared statements
        // Input tidak di-sanitasi
        // =====================================================
        $query = "SELECT * FROM users WHERE username='$username' AND password=MD5('$password')";
        
        // Log untuk forensik
        $log_time = date('Y-m-d H:i:s');
        $log_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $log_ua = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        
        error_log("[$log_time] LOGIN ATTEMPT | IP: $log_ip | User: $username | Query: $query");
        
        // Store login attempt in database (wrapped in try-catch)
        try {
            $log_query = $conn->real_escape_string($query);
            $conn->query("INSERT INTO login_attempts (username, ip_address, user_agent, success, query_used) VALUES ('$username', '$log_ip', '$log_ua', 0, '$log_query')");
        } catch (Exception $e) {
            // Ignore logging errors
        }
        
        $debug_info = "Query: " . htmlspecialchars($query);
        
        $result = $conn->query($query);
        
        if ($result && $result->num_rows > 0) {
            $user = $result->fetch_assoc();
            $_SESSION['user'] = $user['username'];
            $_SESSION['role'] = $user['role'];
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['login_time'] = time();
            
            // Update login attempt to success
            @$conn->query("UPDATE login_attempts SET success=1 WHERE id=LAST_INSERT_ID()");
            
            // Update last login
            @$conn->query("UPDATE users SET last_login=NOW() WHERE id=" . $user['id']);
            
            error_log("[$log_time] LOGIN SUCCESS | IP: $log_ip | User: " . $user['username']);
            
            header('Location: dashboard.php');
            exit;
        } else {
            $error = "Invalid username or password!";
            if ($conn->error) {
                $error .= " (DB Error: " . htmlspecialchars($conn->error) . ")";
            }
            error_log("[$log_time] LOGIN FAILED | IP: $log_ip | User: $username | Error: " . $conn->error);
        }
        
        $conn->close();
    } catch (Exception $e) {
        $error = "System Error: " . htmlspecialchars($e->getMessage());
        error_log("LOGIN ERROR: " . $e->getMessage());
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - TechMart</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 420px;
            overflow: hidden;
        }
        .login-header {
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .login-header h1 { font-size: 1.8em; margin-bottom: 5px; }
        .login-form { padding: 30px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; color: #333; font-weight: 500; }
        .form-group input {
            width: 100%;
            padding: 14px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        .form-group input:focus { border-color: #3498db; outline: none; }
        .btn {
            width: 100%;
            background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
            color: white;
            padding: 14px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(52, 152, 219, 0.4); }
        .alert { padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .alert-danger { background: #fee2e2; color: #dc2626; border: 1px solid #fecaca; }
        .back-link { text-align: center; margin-top: 20px; }
        .back-link a { color: #3498db; text-decoration: none; }
        .debug-box {
            background: #fffbeb;
            border: 1px solid #fbbf24;
            border-radius: 8px;
            padding: 15px;
            margin-top: 20px;
            font-size: 12px;
        }
        .debug-box code { background: #fef3c7; padding: 2px 6px; border-radius: 4px; }
        .hint-box {
            background: #f0fdf4;
            border: 1px solid #22c55e;
            border-radius: 8px;
            padding: 15px;
            margin-top: 15px;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>🔐 TechMart Login</h1>
            <p>Admin Dashboard Access</p>
        </div>
        
        <div class="login-form">
            <?php if($error): ?>
                <div class="alert alert-danger">⚠️ <?php echo $error; ?></div>
            <?php endif; ?>
            
            <form method="POST" autocomplete="off">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" placeholder="Enter username" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" placeholder="Enter password" required>
                </div>
                
                <button type="submit" class="btn">Login</button>
            </form>
            
            <div class="back-link">
                <a href="index.php">← Back to Home</a>
            </div>
            
            <!-- Debug Info untuk Pembelajaran -->
            <div class="debug-box">
                <strong>🔧 Debug Mode (For Learning):</strong><br>
                <code>Default: admin / admin123</code>
                <?php if($debug_info): ?>
                    <br><br><strong>Last Query:</strong><br>
                    <code style="word-break:break-all;"><?php echo $debug_info; ?></code>
                <?php endif; ?>
            </div>
            
            <div class="hint-box">
                <strong>💡 SQL Injection Hints:</strong><br>
                <small>
                • Try: <code>' OR '1'='1</code><br>
                • Try: <code>admin'--</code><br>
                • Try: <code>' UNION SELECT * FROM users--</code>
                </small>
            </div>
        </div>
    </div>
</body>
</html>
