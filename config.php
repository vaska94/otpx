<?php
// Database configuration
define('DB_TYPE', 'mysql'); // 'mysql' or 'sqlite'
define('DB_HOST', 'localhost');
define('DB_NAME', 'totp');
define('DB_USER', 'root');
define('DB_PASS', 'tester');
define('DB_SQLITE_PATH', '../otpx.sqlite'); // Outside web directory for security

// App configuration
define('APP_NAME', 'OTPx');
define('ALLOW_REGISTRATION', true);

// Security
define('SECURE_COOKIES', true);
define('SESSION_LIFETIME', 3600); // 1 hour

// Error reporting (disabled for security)
error_reporting(0);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

// Configure secure session settings
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', SECURE_COOKIES ? 1 : 0);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_lifetime', SESSION_LIFETIME);
ini_set('session.gc_maxlifetime', SESSION_LIFETIME);

// Start session
session_start();

// Check session timeout
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > SESSION_LIFETIME)) {
    session_unset();
    session_destroy();
    session_start();
}
$_SESSION['last_activity'] = time();

// CSRF Token functions
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Input validation constants
define('USERNAME_MIN_LENGTH', 3);
define('USERNAME_MAX_LENGTH', 50);
define('PASSWORD_MIN_LENGTH', 8);
define('PASSWORD_MAX_LENGTH', 128);
define('TOTP_NAME_MAX_LENGTH', 100);
define('TOTP_SECRET_MAX_LENGTH', 1000);

// Input validation and sanitization functions
function sanitizeString($input, $maxLength = null) {
    // Remove null bytes and trim
    $input = str_replace("\0", '', trim($input));
    
    // Apply length limit if specified
    if ($maxLength !== null && strlen($input) > $maxLength) {
        $input = substr($input, 0, $maxLength);
    }
    
    return $input;
}

function validateUsername($username) {
    $username = sanitizeString($username, USERNAME_MAX_LENGTH);
    
    // Check length
    if (strlen($username) < USERNAME_MIN_LENGTH || strlen($username) > USERNAME_MAX_LENGTH) {
        return false;
    }
    
    // Check format: alphanumeric, underscore, hyphen only
    if (!preg_match('/^[a-zA-Z0-9_-]+$/', $username)) {
        return false;
    }
    
    return true;
}

function validatePassword($password) {
    // Check length
    if (strlen($password) < PASSWORD_MIN_LENGTH || strlen($password) > PASSWORD_MAX_LENGTH) {
        return false;
    }
    
    // Password complexity: at least one letter and one number
    if (!preg_match('/^(?=.*[A-Za-z])(?=.*\d)/', $password)) {
        return false;
    }
    
    return true;
}

function validateTOTPName($name) {
    $name = sanitizeString($name, TOTP_NAME_MAX_LENGTH);
    
    // Check length
    if (strlen($name) < 1 || strlen($name) > TOTP_NAME_MAX_LENGTH) {
        return false;
    }
    
    // Allow letters, numbers, spaces, and common symbols
    if (!preg_match('/^[a-zA-Z0-9\s\-_.@()]+$/', $name)) {
        return false;
    }
    
    return true;
}

function validateTOTPSecret($secret) {
    $secret = sanitizeString($secret, TOTP_SECRET_MAX_LENGTH);
    
    // Remove spaces and convert to uppercase
    $secret = strtoupper(str_replace(' ', '', $secret));
    
    // Check length
    if (strlen($secret) < 16 || strlen($secret) > 64) {
        return false;
    }
    
    // Check Base32 format
    if (!preg_match('/^[A-Z2-7]+$/', $secret)) {
        return false;
    }
    
    return true;
}

function getValidationErrors() {
    return [
        'username' => 'Username must be ' . USERNAME_MIN_LENGTH . '-' . USERNAME_MAX_LENGTH . ' characters, alphanumeric, underscore, or hyphen only.',
        'password' => 'Password must be ' . PASSWORD_MIN_LENGTH . '-' . PASSWORD_MAX_LENGTH . ' characters with at least one letter and one number.',
        'totp_name' => 'TOTP name must be 1-' . TOTP_NAME_MAX_LENGTH . ' characters.',
        'totp_secret' => 'TOTP secret must be 16-64 characters in Base32 format (A-Z, 2-7).'
    ];
}

// Cryptographic validation functions
function validateBase64($data) {
    // Check if string is valid Base64
    if (!preg_match('/^[A-Za-z0-9+\/]+=*$/', $data)) {
        return false;
    }
    
    // Verify it can be decoded
    $decoded = base64_decode($data, true);
    if ($decoded === false) {
        return false;
    }
    
    // Re-encode to check for padding issues
    return base64_encode($decoded) === rtrim($data, '=') . str_repeat('=', (4 - strlen(rtrim($data, '=')) % 4) % 4);
}

function validateHex($data) {
    // Check if string contains only hexadecimal characters
    return ctype_xdigit($data) && strlen($data) % 2 === 0;
}

// Database connection
function createDatabase() {
    if (DB_TYPE === 'sqlite') {
        $sqlitePath = DB_SQLITE_PATH;
        $isNewDatabase = !file_exists($sqlitePath);
        $needsInitialization = false;
        
        try {
            $pdo = new PDO(
                "sqlite:" . $sqlitePath,
                null,
                null,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false
                ]
            );
            
            // Check if database needs initialization (new file or empty file)
            if ($isNewDatabase) {
                $needsInitialization = true;
            } else {
                // Check if existing file has tables (handle manually created empty files)
                try {
                    $result = $pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name='users'");
                    if (!$result->fetch()) {
                        $needsInitialization = true;
                    }
                } catch (PDOException $e) {
                    $needsInitialization = true;
                }
            }
            
            // Auto-install tables if needed
            if ($needsInitialization) {
                $pdo->exec("
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ");
                
                $pdo->exec("
                    CREATE TABLE totp_secrets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        name_encrypted TEXT NOT NULL,
                        name_iv VARCHAR(32) NOT NULL,
                        name_salt VARCHAR(32) NOT NULL,
                        encrypted_secret TEXT NOT NULL,
                        secret_iv VARCHAR(32) NOT NULL,
                        secret_salt VARCHAR(32) NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                    )
                ");
                
                $pdo->exec("CREATE INDEX idx_user_id ON totp_secrets(user_id)");
                
                // Set secure permissions on SQLite database file
                if (file_exists($sqlitePath)) {
                    chmod($sqlitePath, 0600);
                }
            }
            
            return $pdo;
        } catch (PDOException $e) {
            // Log detailed error for administrators
            error_log("SQLite connection failed: " . $e->getMessage());
            // Show generic error to users
            die("Database connection failed. Please contact the administrator.");
        }
    } else {
        // MySQL connection with auto-initialization
        try {
            // First try to connect to the database
            $pdo = new PDO(
                "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
                DB_USER,
                DB_PASS,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false
                ]
            );
            
            // Check if tables exist, if not create them
            try {
                $result = $pdo->query("SELECT COUNT(*) FROM users");
            } catch (PDOException $e) {
                // Tables don't exist, create them
                $pdo->exec("
                    CREATE TABLE users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ");
                
                $pdo->exec("
                    CREATE TABLE totp_secrets (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        user_id INT NOT NULL,
                        name_encrypted TEXT NOT NULL,
                        name_iv VARCHAR(32) NOT NULL,
                        name_salt VARCHAR(32) NOT NULL,
                        encrypted_secret TEXT NOT NULL,
                        secret_iv VARCHAR(32) NOT NULL,
                        secret_salt VARCHAR(32) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                    )
                ");
                
                $pdo->exec("CREATE INDEX idx_user_id ON totp_secrets(user_id)");
            }
            
            return $pdo;
        } catch (PDOException $e) {
            // If database doesn't exist, try to create it
            if (strpos($e->getMessage(), 'Unknown database') !== false) {
                try {
                    $pdo = new PDO(
                        "mysql:host=" . DB_HOST . ";charset=utf8mb4",
                        DB_USER,
                        DB_PASS,
                        [
                            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                            PDO::ATTR_EMULATE_PREPARES => false
                        ]
                    );
                    
                    // Create database
                    $pdo->exec("CREATE DATABASE " . DB_NAME . " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
                    $pdo->exec("USE " . DB_NAME);
                    
                    // Create tables
                    $pdo->exec("
                        CREATE TABLE users (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            username VARCHAR(50) UNIQUE NOT NULL,
                            password_hash VARCHAR(255) NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    ");
                    
                    $pdo->exec("
                        CREATE TABLE totp_secrets (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            user_id INT NOT NULL,
                            name_encrypted TEXT NOT NULL,
                            name_iv VARCHAR(32) NOT NULL,
                            name_salt VARCHAR(32) NOT NULL,
                            encrypted_secret TEXT NOT NULL,
                            secret_iv VARCHAR(32) NOT NULL,
                            secret_salt VARCHAR(32) NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                        )
                    ");
                    
                    $pdo->exec("CREATE INDEX idx_user_id ON totp_secrets(user_id)");
                    
                    return $pdo;
                } catch (PDOException $e2) {
                    // Log detailed error for administrators
                    error_log("MySQL database creation failed: " . $e2->getMessage());
                    // Show generic error to users
                    die("Database connection failed. Please contact the administrator.");
                }
            } else {
                // Log detailed error for administrators
                error_log("MySQL connection failed: " . $e->getMessage());
                // Show generic error to users
                die("Database connection failed. Please contact the administrator.");
            }
        }
    }
}

$pdo = createDatabase();