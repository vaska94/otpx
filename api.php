<?php
require_once 'config.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit;
}

// Validate CSRF token
$csrf_token = $_POST['csrf_token'] ?? '';
if (!validateCSRFToken($csrf_token)) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Invalid CSRF token']);
    exit;
}

$action = $_POST['action'] ?? '';
$response = ['success' => false];

switch ($action) {
    case 'add':
        $name_encrypted = sanitizeString($_POST['name_encrypted'] ?? '');
        $name_iv = sanitizeString($_POST['name_iv'] ?? '', 64);
        $name_salt = sanitizeString($_POST['name_salt'] ?? '', 64);
        $encrypted_secret = sanitizeString($_POST['encrypted_secret'] ?? '');
        $secret_iv = sanitizeString($_POST['secret_iv'] ?? '', 64);
        $secret_salt = sanitizeString($_POST['secret_salt'] ?? '', 64);
        
        // Validate inputs
        if (strlen($name_encrypted) < 10 || strlen($name_encrypted) > 5000) {
            $response['error'] = 'Invalid encrypted name length';
        } elseif (!validateBase64($name_encrypted)) {
            $response['error'] = 'Invalid encrypted name format';
        } elseif (strlen($name_iv) < 16 || strlen($name_iv) > 64) {
            $response['error'] = 'Invalid name IV format';
        } elseif (!validateHex($name_iv)) {
            $response['error'] = 'Invalid name IV format';
        } elseif (strlen($name_salt) < 16 || strlen($name_salt) > 64) {
            $response['error'] = 'Invalid name salt format';
        } elseif (!validateHex($name_salt)) {
            $response['error'] = 'Invalid name salt format';
        } elseif (strlen($encrypted_secret) < 10 || strlen($encrypted_secret) > 5000) {
            $response['error'] = 'Invalid encrypted secret length';
        } elseif (!validateBase64($encrypted_secret)) {
            $response['error'] = 'Invalid encrypted secret format';
        } elseif (strlen($secret_iv) < 16 || strlen($secret_iv) > 64) {
            $response['error'] = 'Invalid secret IV format';
        } elseif (!validateHex($secret_iv)) {
            $response['error'] = 'Invalid secret IV format';
        } elseif (strlen($secret_salt) < 16 || strlen($secret_salt) > 64) {
            $response['error'] = 'Invalid secret salt format';
        } elseif (!validateHex($secret_salt)) {
            $response['error'] = 'Invalid secret salt format';
        } elseif ($name_encrypted && $name_iv && $name_salt && $encrypted_secret && $secret_iv && $secret_salt) {
            try {
                $stmt = $pdo->prepare("INSERT INTO totp_secrets (user_id, name_encrypted, name_iv, name_salt, encrypted_secret, secret_iv, secret_salt) VALUES (?, ?, ?, ?, ?, ?, ?)");
                $stmt->execute([$_SESSION['user_id'], $name_encrypted, $name_iv, $name_salt, $encrypted_secret, $secret_iv, $secret_salt]);
                $response['success'] = true;
                $response['id'] = $pdo->lastInsertId();
            } catch (PDOException $e) {
                $response['error'] = 'Failed to add TOTP secret';
            }
        } else {
            $response['error'] = 'Missing required fields';
        }
        break;
        
    case 'delete':
        $id = (int) ($_POST['id'] ?? 0);
        
        if ($id > 0 && $id <= PHP_INT_MAX) {
            try {
                $stmt = $pdo->prepare("DELETE FROM totp_secrets WHERE id = ? AND user_id = ?");
                $stmt->execute([$id, $_SESSION['user_id']]);
                $response['success'] = $stmt->rowCount() > 0;
                if (!$response['success']) {
                    $response['error'] = 'TOTP not found';
                }
            } catch (PDOException $e) {
                $response['error'] = 'Failed to delete TOTP secret';
            }
        } else {
            $response['error'] = 'Invalid ID';
        }
        break;
        
    case 'verify_password':
        $password = $_POST['password'] ?? '';
        
        if ($password) {
            // Get user's password hash
            $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            $user = $stmt->fetch();
            
            if ($user && password_verify($password, $user['password_hash'])) {
                $response['success'] = true;
            } else {
                $response['error'] = 'Incorrect password';
            }
        } else {
            $response['error'] = 'Password required';
        }
        break;
        
    default:
        $response['error'] = 'Invalid action';
}

header('Content-Type: application/json');
echo json_encode($response);