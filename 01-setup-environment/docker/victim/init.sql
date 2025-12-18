-- ============================================
-- Database Initialization Script
-- PT. TechMart Indonesia - E-Commerce Database
-- ============================================

-- Create database
CREATE DATABASE IF NOT EXISTS techmart_db;
USE techmart_db;

-- ============================================
-- TABLE: users
-- ============================================
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role ENUM('admin', 'staff', 'customer') DEFAULT 'customer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE
);

-- Insert default users
INSERT INTO users (username, password, email, role) VALUES 
('admin', MD5('admin123'), 'admin@techmart.co.id', 'admin'),
('staff1', MD5('staff123'), 'staff1@techmart.co.id', 'staff'),
('staff2', MD5('staff456'), 'staff2@techmart.co.id', 'staff');

-- ============================================
-- TABLE: customers
-- ============================================
CREATE TABLE IF NOT EXISTS customers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE,
    phone VARCHAR(20),
    address TEXT,
    city VARCHAR(50),
    postal_code VARCHAR(10),
    credit_card VARCHAR(20),
    cvv VARCHAR(4),
    card_expiry VARCHAR(7),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP
);

-- Insert sample customer data (50 records)
INSERT INTO customers (first_name, last_name, email, phone, address, city, postal_code, credit_card, cvv, card_expiry) VALUES
('Budi', 'Santoso', 'budi.santoso@email.com', '081234567890', 'Jl. Sudirman No. 123', 'Jakarta', '10110', '4532015112830366', '123', '12/2026'),
('Siti', 'Rahayu', 'siti.rahayu@email.com', '081234567891', 'Jl. Gatot Subroto No. 45', 'Jakarta', '12930', '4539578763621486', '456', '03/2027'),
('Ahmad', 'Wijaya', 'ahmad.wijaya@email.com', '081234567892', 'Jl. Thamrin No. 67', 'Jakarta', '10350', '4916338506082832', '789', '06/2026'),
('Dewi', 'Kusuma', 'dewi.kusuma@email.com', '081234567893', 'Jl. Rasuna Said No. 89', 'Jakarta', '12950', '4024007198964305', '012', '09/2027'),
('Rizki', 'Pratama', 'rizki.pratama@email.com', '081234567894', 'Jl. Kuningan No. 12', 'Jakarta', '12940', '4556015886206505', '345', '01/2028'),
('Nurul', 'Hidayah', 'nurul.hidayah@email.com', '081234567895', 'Jl. Senayan No. 34', 'Jakarta', '12180', '4916171848395392', '678', '04/2026'),
('Fajar', 'Setiawan', 'fajar.setiawan@email.com', '081234567896', 'Jl. Kemang No. 56', 'Jakarta', '12730', '4539505652647935', '901', '07/2027'),
('Maya', 'Putri', 'maya.putri@email.com', '081234567897', 'Jl. Pondok Indah No. 78', 'Jakarta', '12310', '4916406379324655', '234', '10/2026'),
('Dimas', 'Nugroho', 'dimas.nugroho@email.com', '081234567898', 'Jl. Kelapa Gading No. 90', 'Jakarta', '14240', '4532148830861507', '567', '02/2028'),
('Rina', 'Wulandari', 'rina.wulandari@email.com', '081234567899', 'Jl. Sunter No. 11', 'Jakarta', '14350', '4916188225489628', '890', '05/2027'),
('Andi', 'Prasetyo', 'andi.prasetyo@email.com', '081345678901', 'Jl. Mangga Dua No. 22', 'Jakarta', '10730', '4539012345678901', '111', '08/2026'),
('Lina', 'Marlina', 'lina.marlina@email.com', '081345678902', 'Jl. Pluit No. 33', 'Jakarta', '14450', '4916234567890123', '222', '11/2027'),
('Hendra', 'Gunawan', 'hendra.gunawan@email.com', '081345678903', 'Jl. Pantai Indah No. 44', 'Jakarta', '14460', '4024345678901234', '333', '03/2028'),
('Yuni', 'Astuti', 'yuni.astuti@email.com', '081345678904', 'Jl. Cempaka Putih No. 55', 'Jakarta', '10510', '4556456789012345', '444', '06/2026'),
('Agus', 'Hermawan', 'agus.hermawan@email.com', '081345678905', 'Jl. Menteng No. 66', 'Jakarta', '10310', '4532567890123456', '555', '09/2027'),
('Ratna', 'Dewi', 'ratna.dewi@email.com', '081456789012', 'Jl. Cikini No. 77', 'Jakarta', '10330', '4916678901234567', '666', '12/2026'),
('Wahyu', 'Saputra', 'wahyu.saputra@email.com', '081456789013', 'Jl. Salemba No. 88', 'Jakarta', '10430', '4539789012345678', '777', '04/2028'),
('Indah', 'Permata', 'indah.permata@email.com', '081456789014', 'Jl. Kramat No. 99', 'Jakarta', '10420', '4024890123456789', '888', '07/2026'),
('Teguh', 'Wibowo', 'teguh.wibowo@email.com', '081456789015', 'Jl. Senen No. 100', 'Jakarta', '10410', '4556901234567890', '999', '10/2027'),
('Fitri', 'Handayani', 'fitri.handayani@email.com', '081456789016', 'Jl. Tanah Abang No. 111', 'Jakarta', '10220', '4532012345678902', '000', '01/2028'),
('Bambang', 'Suryadi', 'bambang.suryadi@email.com', '081567890123', 'Jl. Gambir No. 122', 'Bandung', '40115', '4916123456789013', '121', '05/2026'),
('Nita', 'Sari', 'nita.sari@email.com', '081567890124', 'Jl. Braga No. 133', 'Bandung', '40111', '4539234567890124', '232', '08/2027'),
('Eko', 'Purnomo', 'eko.purnomo@email.com', '081567890125', 'Jl. Dago No. 144', 'Bandung', '40135', '4024345678901235', '343', '11/2026'),
('Wati', 'Susanti', 'wati.susanti@email.com', '081567890126', 'Jl. Riau No. 155', 'Bandung', '40114', '4556456789012346', '454', '02/2028'),
('Joko', 'Widodo', 'joko.widodo@email.com', '081567890127', 'Jl. Diponegoro No. 166', 'Bandung', '40115', '4532567890123457', '565', '06/2027'),
('Ani', 'Yulianti', 'ani.yulianti@email.com', '081678901234', 'Jl. Malioboro No. 177', 'Yogyakarta', '55271', '4916678901234568', '676', '09/2026'),
('Surya', 'Darma', 'surya.darma@email.com', '081678901235', 'Jl. Prawirotaman No. 188', 'Yogyakarta', '55153', '4539789012345679', '787', '12/2027'),
('Mega', 'Puspita', 'mega.puspita@email.com', '081678901236', 'Jl. Kaliurang No. 199', 'Yogyakarta', '55581', '4024890123456780', '898', '03/2028'),
('Rudi', 'Hartono', 'rudi.hartono@email.com', '081678901237', 'Jl. Gejayan No. 200', 'Yogyakarta', '55281', '4556901234567891', '909', '07/2026'),
('Sinta', 'Maharani', 'sinta.maharani@email.com', '081678901238', 'Jl. Seturan No. 211', 'Yogyakarta', '55281', '4532012345678903', '010', '10/2027'),
('Dedi', 'Kurniawan', 'dedi.kurniawan@email.com', '081789012345', 'Jl. Tunjungan No. 222', 'Surabaya', '60275', '4916123456789014', '131', '01/2028'),
('Tari', 'Anggraini', 'tari.anggraini@email.com', '081789012346', 'Jl. Basuki Rahmat No. 233', 'Surabaya', '60271', '4539234567890125', '242', '04/2026'),
('Irfan', 'Hakim', 'irfan.hakim@email.com', '081789012347', 'Jl. Pemuda No. 244', 'Surabaya', '60271', '4024345678901236', '353', '08/2027'),
('Laras', 'Sekar', 'laras.sekar@email.com', '081789012348', 'Jl. Darmo No. 255', 'Surabaya', '60264', '4556456789012347', '464', '11/2026'),
('Bayu', 'Aditya', 'bayu.aditya@email.com', '081789012349', 'Jl. Gubeng No. 266', 'Surabaya', '60281', '4532567890123458', '575', '02/2028'),
('Citra', 'Lestari', 'citra.lestari@email.com', '081890123456', 'Jl. Panglima Sudirman No. 277', 'Malang', '65119', '4916678901234569', '686', '05/2027'),
('Ferry', 'Kristianto', 'ferry.kristianto@email.com', '081890123457', 'Jl. Ijen No. 288', 'Malang', '65119', '4539789012345670', '797', '09/2026'),
('Gita', 'Nirmala', 'gita.nirmala@email.com', '081890123458', 'Jl. Kawi No. 299', 'Malang', '65116', '4024890123456781', '808', '12/2027'),
('Hadi', 'Pranoto', 'hadi.pranoto@email.com', '081890123459', 'Jl. Semeru No. 300', 'Malang', '65112', '4556901234567892', '919', '03/2028'),
('Intan', 'Kartika', 'intan.kartika@email.com', '081890123460', 'Jl. Veteran No. 311', 'Malang', '65145', '4532012345678904', '020', '06/2026'),
('Kiki', 'Amelia', 'kiki.amelia@email.com', '081901234567', 'Jl. A. Yani No. 322', 'Semarang', '50136', '4916123456789015', '141', '10/2027'),
('Leo', 'Firmansyah', 'leo.firmansyah@email.com', '081901234568', 'Jl. Pandanaran No. 333', 'Semarang', '50134', '4539234567890126', '252', '01/2028'),
('Mira', 'Wahyuni', 'mira.wahyuni@email.com', '081901234569', 'Jl. Simpang Lima No. 344', 'Semarang', '50134', '4024345678901237', '363', '04/2026'),
('Niko', 'Pratama', 'niko.pratama@email.com', '081901234570', 'Jl. Gajahmada No. 355', 'Semarang', '50134', '4556456789012348', '474', '07/2027'),
('Olive', 'Safitri', 'olive.safitri@email.com', '081901234571', 'Jl. MT Haryono No. 366', 'Semarang', '50242', '4532567890123459', '585', '11/2026'),
('Putra', 'Ramadhan', 'putra.ramadhan@email.com', '082012345678', 'Jl. Gatot Subroto No. 377', 'Medan', '20235', '4916678901234560', '696', '02/2028'),
('Qori', 'Nabila', 'qori.nabila@email.com', '082012345679', 'Jl. Imam Bonjol No. 388', 'Medan', '20112', '4539789012345671', '707', '05/2027'),
('Rama', 'Wijaksono', 'rama.wijaksono@email.com', '082012345680', 'Jl. Diponegoro No. 399', 'Medan', '20152', '4024890123456782', '818', '08/2026'),
('Sarah', 'Putri', 'sarah.putri@email.com', '082012345681', 'Jl. Zainul Arifin No. 400', 'Medan', '20152', '4556901234567893', '929', '12/2027'),
('Toni', 'Budiman', 'toni.budiman@email.com', '082012345682', 'Jl. Brigjend Katamso No. 411', 'Medan', '20158', '4532012345678905', '030', '03/2028');

-- ============================================
-- TABLE: products
-- ============================================
CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(12,2),
    stock INT DEFAULT 0,
    category VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO products (name, description, price, stock, category) VALUES
('Smartphone Pro X', 'Flagship smartphone with 6.7" display', 5999000, 100, 'Electronics'),
('Laptop Ultra', '15.6" laptop with Intel i7', 12999000, 50, 'Electronics'),
('Wireless Headphone', 'Noise cancelling bluetooth headphone', 899000, 200, 'Electronics'),
('Smart Watch', 'Fitness tracker with heart rate monitor', 1499000, 150, 'Electronics'),
('Tablet Pro', '10" tablet with stylus support', 4999000, 75, 'Electronics');

-- ============================================
-- TABLE: orders
-- ============================================
CREATE TABLE IF NOT EXISTS orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    customer_id INT,
    product_id INT,
    quantity INT,
    total_price DECIMAL(12,2),
    status ENUM('pending', 'processing', 'shipped', 'delivered', 'cancelled') DEFAULT 'pending',
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- ============================================
-- TABLE: audit_log (untuk forensik)
-- ============================================
CREATE TABLE IF NOT EXISTS audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    action VARCHAR(50),
    table_name VARCHAR(50),
    record_id INT,
    user_id INT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details TEXT
);

-- ============================================
-- TABLE: login_attempts (untuk forensik)
-- ============================================
CREATE TABLE IF NOT EXISTS login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    ip_address VARCHAR(45),
    user_agent TEXT,
    success BOOLEAN,
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    query_used TEXT
);

-- Create user for application
CREATE USER IF NOT EXISTS 'techmart_user'@'%' IDENTIFIED BY 'password123';
GRANT ALL PRIVILEGES ON techmart_db.* TO 'techmart_user'@'%';
FLUSH PRIVILEGES;
