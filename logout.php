<?php
require_once 'config.php';

// Complete session cleanup to prevent session fixation attacks
session_unset();           // Clear all session variables
session_destroy();         // Destroy the session data
session_regenerate_id(true); // Generate new session ID

// Clear session cookie from browser
if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), '', time() - 3600, '/');
}

// Redirect to login
header('Location: login.php');
exit;