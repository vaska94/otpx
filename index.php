<?php
require_once 'config.php';

// Redirect to login if not authenticated
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

// Get user data
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_SESSION['user_id']]);
$user = $stmt->fetch();

// Get user's TOTP entries (encrypted)
$stmt = $pdo->prepare("SELECT * FROM totp_secrets WHERE user_id = ? ORDER BY id");
$stmt->execute([$_SESSION['user_id']]);
$secrets = $stmt->fetchAll();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo APP_NAME; ?></title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    <header>
        <div class="container">
            <div class="header-content">
                <h1><?php echo APP_NAME; ?></h1>
                <div class="user-menu">
                    <div class="user-info">
                        <svg class="icon" viewBox="0 0 20 20">
                            <path d="M10 10a3 3 0 100-6 3 3 0 000 6zM3.465 14.493a1.23 1.23 0 00.41 1.412A9.957 9.957 0 0010 18c2.31 0 4.438-.784 6.131-2.1.43-.333.604-.903.408-1.41a7.002 7.002 0 00-13.074.003z"/>
                        </svg>
                        <span><?php echo htmlspecialchars($user['username']); ?></span>
                    </div>
                    <button onclick="showExportModal()" class="btn btn-secondary">Export</button>
                    <button onclick="showImportModal()" class="btn btn-secondary">Import</button>
                    <a href="logout.php" class="btn btn-danger">Logout</a>
                </div>
            </div>
        </div>
    </header>

    <main>
        <div class="container">
            <div class="add-section">
                <button onclick="showAddModal()" class="btn btn-primary add-button">
                    <svg viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd"/>
                    </svg>
                    Add New TOTP
                </button>
            </div>

            <div id="totp-grid" class="totp-grid">
                <?php foreach ($secrets as $secret): ?>
                    <div class="totp-card" data-id="<?php echo $secret['id']; ?>" 
                         data-name-encrypted="<?php echo htmlspecialchars($secret['name_encrypted']); ?>"
                         data-name-iv="<?php echo htmlspecialchars($secret['name_iv']); ?>"
                         data-name-salt="<?php echo htmlspecialchars($secret['name_salt']); ?>"
                         data-encrypted="<?php echo htmlspecialchars($secret['encrypted_secret']); ?>"
                         data-iv="<?php echo htmlspecialchars($secret['secret_iv']); ?>"
                         data-salt="<?php echo htmlspecialchars($secret['secret_salt']); ?>">
                        <div class="totp-header">
                            <h3 class="totp-name">Loading...</h3>
                            <button onclick="deleteTotp(<?php echo $secret['id']; ?>)" class="totp-delete">
                                <svg viewBox="0 0 20 20" fill="currentColor">
                                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/>
                                </svg>
                            </button>
                        </div>
                        <div class="totp-code-section">
                            <div class="totp-code" onclick="copyCode(this)">------</div>
                            <div class="totp-timer">
                                <svg class="timer-svg" viewBox="0 0 48 48">
                                    <circle class="timer-bg" cx="24" cy="24" r="21" />
                                    <circle class="timer-progress" cx="24" cy="24" r="21" />
                                </svg>
                                <span class="timer-text">30</span>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    </main>

    <!-- Add TOTP Modal -->
    <div id="addModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title">Add New TOTP</h2>
            </div>
            <form id="addForm">
                <div class="modal-body">
                    <input type="text" id="totpName" class="modal-input" 
                           placeholder="Name (e.g., GitHub)" 
                           maxlength="<?php echo TOTP_NAME_MAX_LENGTH; ?>"
                           pattern="[a-zA-Z0-9\s\-_.@()]+"
                           title="TOTP name must be 1-<?php echo TOTP_NAME_MAX_LENGTH; ?> characters"
                           required>
                    <input type="text" id="totpSecret" class="modal-input" 
                           placeholder="Secret Key (Base32 format)" 
                           maxlength="64"
                           pattern="[A-Z2-7\s]+"
                           title="TOTP secret must be 16-64 characters in Base32 format (A-Z, 2-7)"
                           required>
                </div>
                <div class="modal-footer">
                    <button type="button" onclick="closeModal()" class="btn btn-secondary">Cancel</button>
                    <button type="submit" class="btn btn-primary">Add</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Export Modal -->
    <div id="exportModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title">Export TOTP Secrets</h2>
            </div>
            <div class="modal-body">
                <p>Enter your login password to export your secrets:</p>
                <input type="password" id="exportPassword" class="modal-input" placeholder="Login Password">
                <textarea id="exportData" class="modal-textarea" readonly style="display:none;"></textarea>
            </div>
            <div class="modal-footer">
                <button onclick="closeModal()" class="btn btn-secondary">Cancel</button>
                <button onclick="exportSecrets()" class="btn btn-primary">Export</button>
            </div>
        </div>
    </div>

    <!-- Import Modal -->
    <div id="importModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title">Import TOTP Secrets</h2>
            </div>
            <div class="modal-body">
                <textarea id="importData" class="modal-textarea" placeholder="Paste exported data here" rows="10"></textarea>
                <input type="password" id="importPassword" class="modal-input" placeholder="Login Password">
            </div>
            <div class="modal-footer">
                <button onclick="closeModal()" class="btn btn-secondary">Cancel</button>
                <button onclick="importSecrets()" class="btn btn-primary">Import</button>
            </div>
        </div>
    </div>

    <!-- Password Prompt (for decryption on page load) -->
    <div id="passwordModal" class="modal" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title">Enter Password</h2>
            </div>
            <div class="modal-body">
                <p>Enter your login password to decrypt your TOTP secrets:</p>
                <input type="password" id="decryptPassword" class="modal-input" placeholder="Login Password" autofocus>
            </div>
            <div class="modal-footer">
                <button onclick="decryptAllSecrets()" class="btn btn-primary btn-large">Unlock</button>
            </div>
        </div>
    </div>

    <script>
        // Global CSRF token
        window.csrfToken = '<?php echo generateCSRFToken(); ?>';
    </script>
    <script src="assets/crypto-js.min.js"></script>
    <script src="assets/script.js"></script>
</body>
</html>