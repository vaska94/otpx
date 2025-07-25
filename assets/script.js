// Global variables
let userPassword = null;
let totpSecrets = new Map();
let totpNames = new Map();
let updateInterval;

// TOTP generation
function generateTOTP(secret) {
    const epoch = Math.floor(Date.now() / 1000);
    const time = Math.floor(epoch / 30);
    
    // Convert time to 8-byte buffer
    const timeBuffer = new ArrayBuffer(8);
    const timeView = new DataView(timeBuffer);
    timeView.setUint32(4, time, false);
    
    // Base32 decode the secret
    const base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    for (let i = 0; i < secret.toUpperCase().length; i++) {
        const val = base32chars.indexOf(secret.toUpperCase()[i]);
        if (val !== -1) {
            bits += val.toString(2).padStart(5, '0');
        }
    }
    
    const bytes = [];
    for (let i = 0; i < bits.length; i += 8) {
        bytes.push(parseInt(bits.substr(i, 8), 2));
    }
    
    // HMAC-SHA1
    const key = CryptoJS.lib.WordArray.create(new Uint8Array(bytes));
    const message = CryptoJS.lib.WordArray.create(new Uint8Array(timeBuffer));
    const hmac = CryptoJS.HmacSHA1(message, key);
    const hmacBytes = hexToBytes(hmac.toString());
    
    // Dynamic truncation
    const offset = hmacBytes[hmacBytes.length - 1] & 0xf;
    const code = ((hmacBytes[offset] & 0x7f) << 24) |
                 ((hmacBytes[offset + 1] & 0xff) << 16) |
                 ((hmacBytes[offset + 2] & 0xff) << 8) |
                 (hmacBytes[offset + 3] & 0xff);
    
    const otp = (code % 1000000).toString().padStart(6, '0');
    return otp;
}

function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

// Encryption/Decryption functions
function deriveKey(password, salt) {
    return CryptoJS.PBKDF2(password, CryptoJS.enc.Hex.parse(salt), {
        keySize: 256/32,
        iterations: 15000
    });
}

function encryptSecret(secret, password) {
    // Generate cryptographically secure random values with entropy differentiation
    const salt = CryptoJS.lib.WordArray.random(128/8).toString();
    const iv = CryptoJS.lib.WordArray.random(128/8).toString();
    
    // Ensure IV and salt are never identical by adding microsecond entropy
    const entropyDiff = Date.now().toString(16) + Math.random().toString(16).substr(2, 8);
    const finalIv = CryptoJS.SHA256(iv + entropyDiff).toString().substr(0, 32);
    
    const key = deriveKey(password, salt);
    
    const encrypted = CryptoJS.AES.encrypt(secret, key, {
        iv: CryptoJS.enc.Hex.parse(finalIv)
    });
    
    return {
        encrypted: encrypted.toString(),
        salt: salt,
        iv: finalIv
    };
}

function decryptSecret(encryptedData, password, salt, iv) {
    const key = deriveKey(password, salt);
    
    const decrypted = CryptoJS.AES.decrypt(encryptedData, key, {
        iv: CryptoJS.enc.Hex.parse(iv)
    });
    
    return decrypted.toString(CryptoJS.enc.Utf8);
}

// UI Functions
function showAddModal() {
    document.getElementById('addModal').style.display = 'flex';
}

function showExportModal() {
    document.getElementById('exportModal').style.display = 'flex';
}

function showImportModal() {
    document.getElementById('importModal').style.display = 'flex';
}

function closeModal() {
    document.querySelectorAll('.modal').forEach(modal => {
        modal.style.display = 'none';
    });
    document.getElementById('exportData').style.display = 'none';
    document.getElementById('exportData').value = '';
    document.getElementById('importData').value = '';
}

// Initialize app on page load
function initializeApp() {
    // Always show password modal for security - no auto-login from sessionStorage
    document.getElementById('passwordModal').style.display = 'flex';
}

// Decrypt all secrets and names with given password
function decryptAllSecretsWithPassword(password) {
    document.querySelectorAll('.totp-card').forEach(card => {
        const id = card.dataset.id;
        
        // Decrypt name
        const nameEncrypted = card.dataset.nameEncrypted;
        const nameIv = card.dataset.nameIv;
        const nameSalt = card.dataset.nameSalt;
        
        // Decrypt secret
        const encrypted = card.dataset.encrypted;
        const iv = card.dataset.iv;
        const salt = card.dataset.salt;
        
        try {
            // Decrypt name
            const name = decryptSecret(nameEncrypted, password, nameSalt, nameIv);
            if (name) {
                totpNames.set(id, name);
                // Update the UI with decrypted name
                const nameElement = card.querySelector('.totp-name');
                nameElement.textContent = name;
            }
            
            // Decrypt secret
            const secret = decryptSecret(encrypted, password, salt, iv);
            if (secret) {
                totpSecrets.set(id, secret);
            }
        } catch (e) {
            console.error('Failed to decrypt data:', e);
            // Show error in UI
            const nameElement = card.querySelector('.totp-name');
            nameElement.textContent = 'Decryption Error';
        }
    });
}

// Decrypt all secrets on password entry
async function decryptAllSecrets() {
    const password = document.getElementById('decryptPassword').value;
    if (!password) {
        alert('Please enter your password');
        return;
    }
    
    // First verify this is the correct login password
    const formData = new FormData();
    formData.append('action', 'verify_password');
    formData.append('password', password);
    formData.append('csrf_token', getCSRFToken());
    
    try {
        const response = await fetch('api.php', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        if (!result.success) {
            alert('Incorrect login password');
            return;
        }
    } catch (error) {
        alert('Error verifying password: ' + error.message);
        return;
    }
    
    // Password verified - now use it for decryption
    userPassword = password;
    decryptAllSecretsWithPassword(password);
    
    document.getElementById('passwordModal').style.display = 'none';
    startTOTPUpdate();
}

// Update TOTP codes
function updateTOTPCodes() {
    const currentTime = Math.floor(Date.now() / 1000);
    const timeRemaining = 30 - (currentTime % 30);
    
    document.querySelectorAll('.totp-card').forEach(card => {
        const id = card.dataset.id;
        const secret = totpSecrets.get(id);
        
        if (secret) {
            try {
                const code = generateTOTP(secret);
                card.querySelector('.totp-code').textContent = code;
            } catch (e) {
                card.querySelector('.totp-code').textContent = 'ERROR';
            }
        }
        
        // Update timer
        const timerText = card.querySelector('.timer-text');
        const timerProgress = card.querySelector('.timer-progress');
        
        timerText.textContent = timeRemaining;
        const progress = (timeRemaining / 30) * 100;
        const circumference = 2 * Math.PI * 21; // Updated radius
        const offset = circumference - (progress / 100 * circumference);
        timerProgress.style.strokeDashoffset = offset;
        
        // Add warning class when less than 5 seconds remaining
        if (timeRemaining <= 5) {
            timerProgress.classList.add('warning');
            timerText.classList.add('warning');
        } else {
            timerProgress.classList.remove('warning');
            timerText.classList.remove('warning');
        }
    });
}

function startTOTPUpdate() {
    updateTOTPCodes();
    updateInterval = setInterval(updateTOTPCodes, 1000);
}

// Copy code when clicked
function copyCode(codeElement) {
    const code = codeElement.textContent;
    
    if (code !== '------' && code !== 'ERROR') {
        navigator.clipboard.writeText(code).then(() => {
            codeElement.classList.add('copied');
            setTimeout(() => {
                codeElement.classList.remove('copied');
            }, 1000);
        }).catch(() => {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = code;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            
            codeElement.classList.add('copied');
            setTimeout(() => {
                codeElement.classList.remove('copied');
            }, 1000);
        });
    }
}

// Client-side validation functions
function validateTOTPInputs(name, secret) {
    // Validate name
    if (name.length < 1 || name.length > 100) {
        return 'TOTP name must be 1-100 characters';
    }
    if (!/^[a-zA-Z0-9\s\-_.@()]+$/.test(name)) {
        return 'TOTP name contains invalid characters';
    }
    
    // Clean and validate secret
    const cleanSecret = secret.replace(/\s/g, '').toUpperCase();
    if (cleanSecret.length < 16 || cleanSecret.length > 64) {
        return 'TOTP secret must be 16-64 characters';
    }
    if (!/^[A-Z2-7]+$/.test(cleanSecret)) {
        return 'Warning: TOTP secret must be in Base32 format (A-Z, 2-7). Invalid secrets will not generate working codes.';
    }
    
    return null; // Valid
}

// Enhanced validation with user warning
function validateTOTPInputsWithWarning(name, secret) {
    const basicValidation = validateTOTPInputs(name, secret);
    if (basicValidation && basicValidation.startsWith('Warning:')) {
        return confirm(basicValidation + '\n\nDo you want to continue anyway?') ? null : basicValidation;
    }
    return basicValidation;
}

// Add new TOTP
document.getElementById('addForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const name = document.getElementById('totpName').value.trim();
    const secret = document.getElementById('totpSecret').value.replace(/\s/g, '');
    
    // Client-side validation with user warning
    const validationError = validateTOTPInputsWithWarning(name, secret);
    if (validationError) {
        alert(validationError);
        return;
    }
    
    if (!userPassword) {
        alert('Please unlock your secrets first');
        return;
    }
    
    // Encrypt both name and secret with separate IV/salt
    const encryptedSecret = encryptSecret(secret, userPassword);
    const encryptedName = encryptSecret(name, userPassword);
    
    const formData = new FormData();
    formData.append('action', 'add');
    formData.append('name_encrypted', encryptedName.encrypted);
    formData.append('name_iv', encryptedName.iv);
    formData.append('name_salt', encryptedName.salt);
    formData.append('encrypted_secret', encryptedSecret.encrypted);
    formData.append('secret_iv', encryptedSecret.iv);
    formData.append('secret_salt', encryptedSecret.salt);
    formData.append('csrf_token', getCSRFToken());
    
    try {
        const response = await fetch('api.php', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        if (result.success) {
            location.reload();
        } else {
            alert(result.error || 'Failed to add TOTP');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
});

// Delete TOTP
async function deleteTotp(id) {
    if (!confirm('Are you sure you want to delete this TOTP?')) {
        return;
    }
    
    const formData = new FormData();
    formData.append('action', 'delete');
    formData.append('id', id);
    formData.append('csrf_token', getCSRFToken());
    
    try {
        const response = await fetch('api.php', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        if (result.success) {
            location.reload();
        } else {
            alert(result.error || 'Failed to delete TOTP');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// Export secrets
async function exportSecrets() {
    const password = document.getElementById('exportPassword').value;
    if (!password) {
        alert('Please enter your login password');
        return;
    }
    
    // Verify this is the correct login password
    const formData = new FormData();
    formData.append('action', 'verify_password');
    formData.append('password', password);
    formData.append('csrf_token', getCSRFToken());
    
    try {
        const response = await fetch('api.php', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        if (!result.success) {
            alert('Incorrect login password');
            return;
        }
    } catch (error) {
        alert('Error verifying password: ' + error.message);
        return;
    }
    
    // Password verified - check if it matches the encryption password
    if (password !== userPassword) {
        alert('Password verified, but this doesn\'t match your current encryption password. Please unlock your TOTPs first with this password.');
        return;
    }
    
    const exportData = [];
    document.querySelectorAll('.totp-card').forEach(card => {
        const id = card.dataset.id;
        const name = totpNames.get(id);
        const secret = totpSecrets.get(id);
        
        if (name && secret) {
            exportData.push({
                name: name,
                secret: secret
            });
        }
    });
    
    const jsonData = JSON.stringify(exportData, null, 2);
    document.getElementById('exportData').style.display = 'block';
    document.getElementById('exportData').value = jsonData;
}

// Import secrets
async function importSecrets() {
    const importData = document.getElementById('importData').value;
    const password = document.getElementById('importPassword').value;
    
    if (!password) {
        alert('Please enter your login password');
        return;
    }
    
    // Verify this is the correct login password
    const formData = new FormData();
    formData.append('action', 'verify_password');
    formData.append('password', password);
    formData.append('csrf_token', getCSRFToken());
    
    try {
        const response = await fetch('api.php', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        if (!result.success) {
            alert('Incorrect login password');
            return;
        }
    } catch (error) {
        alert('Error verifying password: ' + error.message);
        return;
    }
    
    // Password verified - check if it matches the encryption password
    if (password !== userPassword) {
        alert('Password verified, but this doesn\'t match your current encryption password. Please unlock your TOTPs first with this password.');
        return;
    }
    
    try {
        const secrets = JSON.parse(importData);
        let imported = 0;
        
        for (const item of secrets) {
            if (item.name && item.secret) {
                // Encrypt both name and secret with separate IV/salt
                const encryptedSecret = encryptSecret(item.secret, userPassword);
                const encryptedName = encryptSecret(item.name, userPassword);
                
                const formData = new FormData();
                formData.append('action', 'add');
                formData.append('name_encrypted', encryptedName.encrypted);
                formData.append('name_iv', encryptedName.iv);
                formData.append('name_salt', encryptedName.salt);
                formData.append('encrypted_secret', encryptedSecret.encrypted);
                formData.append('secret_iv', encryptedSecret.iv);
                formData.append('secret_salt', encryptedSecret.salt);
                formData.append('csrf_token', getCSRFToken());
                
                const response = await fetch('api.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                if (result.success) {
                    imported++;
                }
            }
        }
        
        alert(`Imported ${imported} TOTP secrets`);
        location.reload();
    } catch (error) {
        alert('Invalid import data: ' + error.message);
    }
}

// Close modal on outside click
window.onclick = function(event) {
    if (event.target.classList.contains('modal') && event.target.id !== 'passwordModal') {
        closeModal();
    }
}

// Initialize app when page loads
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});