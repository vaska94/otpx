<?php
require_once 'config.php';

// Check if registration is allowed
if (!ALLOW_REGISTRATION) {
    header('Location: login.php');
    exit;
}

// Redirect if already logged in
if (isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token
    $csrf_token = $_POST['csrf_token'] ?? '';
    if (!validateCSRFToken($csrf_token)) {
        $error = 'Invalid request. Please try again.';
    } else {
        $username = sanitizeString($_POST['username'] ?? '', USERNAME_MAX_LENGTH);
        $password = $_POST['password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';
        
        if ($username && $password && $confirm_password) {
            // Validate username
            if (!validateUsername($username)) {
                $errors = getValidationErrors();
                $error = $errors['username'];
            } elseif ($password !== $confirm_password) {
                $error = 'Passwords do not match';
            } elseif (!validatePassword($password)) {
                $errors = getValidationErrors();
                $error = $errors['password'];
            } else {
                // Check if username already exists
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
                $stmt->execute([$username]);
                
                if ($stmt->fetchColumn() > 0) {
                    $error = 'Username already exists';
                } else {
                    // Create user
                    $password_hash = password_hash($password, PASSWORD_DEFAULT);
                    $stmt = $pdo->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)");
                    
                    try {
                        $stmt->execute([$username, $password_hash]);
                        
                        // Auto-login after successful registration
                        session_regenerate_id(true);
                        $user_id = $pdo->lastInsertId();
                        $_SESSION['user_id'] = $user_id;
                        $_SESSION['username'] = $username;
                        
                        header('Location: index.php');
                        exit;
                    } catch (PDOException $e) {
                        $error = 'Registration failed. Please try again.';
                    }
                }
            }
        } else {
            $error = 'Please fill in all fields';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - <?php echo APP_NAME; ?></title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    <div class="auth-container">
        <div class="auth-box">
            <div class="auth-logo">
                <h1><?php echo APP_NAME; ?></h1>
            </div>
            <h2 class="auth-title">Register</h2>
            
            <?php if ($error): ?>
                <div class="alert alert-error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>
            
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                <div class="form-group">
                    <label class="form-label">Username</label>
                    <input type="text" name="username" class="form-input" 
                           minlength="<?php echo USERNAME_MIN_LENGTH; ?>" 
                           maxlength="<?php echo USERNAME_MAX_LENGTH; ?>" 
                           pattern="[a-zA-Z0-9_-]+" 
                           title="Username must be <?php echo USERNAME_MIN_LENGTH; ?>-<?php echo USERNAME_MAX_LENGTH; ?> characters, alphanumeric, underscore, or hyphen only"
                           required autofocus>
                </div>
                <div class="form-group">
                    <label class="form-label">Password</label>
                    <input type="password" name="password" class="form-input" 
                           minlength="<?php echo PASSWORD_MIN_LENGTH; ?>" 
                           maxlength="<?php echo PASSWORD_MAX_LENGTH; ?>"
                           pattern="^(?=.*[A-Za-z])(?=.*\d).+$"
                           title="Password must be <?php echo PASSWORD_MIN_LENGTH; ?>-<?php echo PASSWORD_MAX_LENGTH; ?> characters with at least one letter and one number"
                           required>
                </div>
                <div class="form-group">
                    <label class="form-label">Confirm Password</label>
                    <input type="password" name="confirm_password" class="form-input" 
                           minlength="<?php echo PASSWORD_MIN_LENGTH; ?>" 
                           maxlength="<?php echo PASSWORD_MAX_LENGTH; ?>"
                           required>
                </div>
                <button type="submit" class="btn btn-primary form-submit btn-large">Register</button>
            </form>
            
            <p class="auth-link">
                Already have an account? <a href="login.php">Login</a>
            </p>
        </div>
    </div>
</body>
</html>