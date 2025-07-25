<?php
require_once 'config.php';

// Redirect if already logged in
if (isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token
    $csrf_token = $_POST['csrf_token'] ?? '';
    if (!validateCSRFToken($csrf_token)) {
        $error = 'Invalid request. Please try again.';
    } else {
        $username = sanitizeString($_POST['username'] ?? '', USERNAME_MAX_LENGTH);
        $password = $_POST['password'] ?? '';
        
        if ($username && $password) {
            // Basic validation for login (less strict than registration)
            if (strlen($username) > USERNAME_MAX_LENGTH || strlen($password) > PASSWORD_MAX_LENGTH) {
                $error = 'Invalid input length';
            } elseif (strlen($username) < USERNAME_MIN_LENGTH) {
                $error = 'Invalid username or password';
            } else {
                $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
                $stmt->execute([$username]);
                $user = $stmt->fetch();
                
                if ($user && password_verify($password, $user['password_hash'])) {
                    // Regenerate session ID for security
                    session_regenerate_id(true);
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    header('Location: index.php');
                    exit;
                } else {
                    $error = 'Invalid username or password';
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
    <title>Login - <?php echo APP_NAME; ?></title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    <div class="auth-container">
        <div class="auth-box">
            <div class="auth-logo">
                <h1><?php echo APP_NAME; ?></h1>
            </div>
            <h2 class="auth-title">Login</h2>
            
            <?php if ($error): ?>
                <div class="alert alert-error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                <div class="form-group">
                    <label class="form-label">Username</label>
                    <input type="text" name="username" class="form-input" 
                           maxlength="<?php echo USERNAME_MAX_LENGTH; ?>" 
                           required autofocus>
                </div>
                <div class="form-group">
                    <label class="form-label">Password</label>
                    <input type="password" name="password" class="form-input" 
                           maxlength="<?php echo PASSWORD_MAX_LENGTH; ?>"
                           required>
                </div>
                <button type="submit" class="btn btn-primary form-submit btn-large">Login</button>
            </form>
            
            <?php if (ALLOW_REGISTRATION): ?>
            <p class="auth-link">
                Don't have an account? <a href="register.php">Register</a>
            </p>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>