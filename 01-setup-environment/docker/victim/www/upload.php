<?php
/**
 * File Upload Page - VULNERABLE TO UNRESTRICTED FILE UPLOAD
 * PT. TechMart Indonesia
 * FOR EDUCATIONAL PURPOSES ONLY
 * 
 * VULNERABILITIES:
 * 1. No file type validation
 * 2. No file extension validation
 * 3. No file size limit
 * 4. Files stored in web-accessible directory
 */
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Check if logged in (tapi masih bisa di-bypass)
if (!isset($_SESSION['user'])) {
    // VULNERABILITY: Parameter bypass
    if (!isset($_GET['bypass']) && !isset($_POST['bypass'])) {
        header('Location: login.php');
        exit;
    }
}

$upload_dir = 'uploads/';
$message = '';
$error = '';

// Create upload directory if not exists
if (!file_exists($upload_dir)) {
    mkdir($upload_dir, 0777, true);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];
    
    // Log untuk forensik
    $log_time = date('Y-m-d H:i:s');
    $log_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    error_log("[$log_time] FILE UPLOAD | IP: $log_ip | File: {$file['name']} | Size: {$file['size']} | Type: {$file['type']}");
    
    // =====================================================
    // VULNERABILITY: NO VALIDATION!
    // Tidak ada pengecekan tipe file
    // Tidak ada pengecekan ekstensi
    // File bisa diupload langsung ke web directory
    // =====================================================
    
    $target_path = $upload_dir . basename($file['name']);
    
    // VULNERABILITY: Directly move uploaded file without any validation
    if (move_uploaded_file($file['tmp_name'], $target_path)) {
        $message = "File uploaded successfully: " . htmlspecialchars($file['name']);
        $message .= "<br>Access URL: <a href='$target_path'>$target_path</a>";
        
        error_log("[$log_time] FILE UPLOAD SUCCESS | IP: $log_ip | Path: $target_path");
        
        // Store in audit log
        try {
            $host = getenv('MYSQL_HOST') ?: 'victim-db';
            $user = getenv('MYSQL_USER') ?: 'techmart_user';
            $pass = getenv('MYSQL_PASSWORD') ?: 'password123';
            $db = getenv('MYSQL_DATABASE') ?: 'techmart_db';
            
            $conn = @new mysqli($host, $user, $pass, $db);
            if (!$conn->connect_error) {
                $filename = $conn->real_escape_string($file['name']);
                $filepath = $conn->real_escape_string($target_path);
                $ip = $conn->real_escape_string($log_ip);
                $conn->query("INSERT INTO audit_log (action, details, ip_address, user_agent) VALUES ('FILE_UPLOAD', 'File: $filename, Path: $filepath', '$ip', '" . ($_SERVER['HTTP_USER_AGENT'] ?? '') . "')");
                $conn->close();
            }
        } catch (Exception $e) {
            // Ignore
        }
    } else {
        $error = "Failed to upload file.";
        error_log("[$log_time] FILE UPLOAD FAILED | IP: $log_ip | Error: Move failed");
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Upload - PT. TechMart Indonesia</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; flex-direction: column; }
        .navbar { background: linear-gradient(135deg, #1e3c72, #2a5298); padding: 15px 30px; color: white; }
        .navbar h1 { font-size: 1.5rem; }
        .container { max-width: 600px; margin: 50px auto; padding: 0 20px; }
        .card { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 5px 20px rgba(0,0,0,0.1); }
        .card h2 { text-align: center; margin-bottom: 30px; color: #333; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; font-weight: 500; color: #555; }
        .form-group input[type="file"] { width: 100%; padding: 15px; border: 2px dashed #ddd; border-radius: 8px; cursor: pointer; }
        .form-group input[type="file"]:hover { border-color: #1e3c72; }
        .btn { width: 100%; padding: 15px; background: linear-gradient(135deg, #1e3c72, #2a5298); color: white; border: none; border-radius: 8px; font-size: 1rem; cursor: pointer; transition: transform 0.2s; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(30,60,114,0.3); }
        .message { padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .message.success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .message.error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .warning { background: #fff3cd; padding: 15px; border-radius: 8px; margin-bottom: 20px; color: #856404; font-size: 0.9rem; }
        .back-link { display: inline-block; margin-top: 20px; color: #1e3c72; text-decoration: none; }
        .uploaded-files { margin-top: 30px; }
        .uploaded-files h3 { margin-bottom: 15px; color: #333; }
        .file-list { list-style: none; }
        .file-list li { padding: 10px; background: #f8f9fa; margin-bottom: 5px; border-radius: 5px; }
        .file-list a { color: #1e3c72; text-decoration: none; }
    </style>
</head>
<body>
    <nav class="navbar">
        <h1>🛒 PT. TechMart Indonesia - File Upload</h1>
    </nav>
    
    <div class="container">
        <div class="card">
            <h2>📤 Upload File</h2>
            
            <div class="warning">
                ⚠️ <strong>Warning:</strong> This upload form is intentionally vulnerable for educational purposes.
            </div>
            
            <?php if ($message): ?>
                <div class="message success"><?php echo $message; ?></div>
            <?php endif; ?>
            
            <?php if ($error): ?>
                <div class="message error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <form method="POST" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="file">Select file to upload:</label>
                    <input type="file" name="file" id="file" required>
                </div>
                <button type="submit" class="btn">Upload File</button>
            </form>
            
            <?php
            // List uploaded files
            $files = glob($upload_dir . '*');
            if ($files):
            ?>
            <div class="uploaded-files">
                <h3>📁 Uploaded Files:</h3>
                <ul class="file-list">
                    <?php foreach ($files as $file): ?>
                        <li>
                            <a href="<?php echo htmlspecialchars($file); ?>" target="_blank">
                                <?php echo htmlspecialchars(basename($file)); ?>
                            </a>
                            (<?php echo number_format(filesize($file)); ?> bytes)
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
            <?php endif; ?>
            
            <a href="dashboard.php" class="back-link">← Back to Dashboard</a>
        </div>
    </div>
</body>
</html>
