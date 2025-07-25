# OTPx - Secure TOTP Dashboard

A privacy-focused, web-based Two-Factor Authentication (2FA) token manager with client-side encryption. Similar to Google Authenticator but with enhanced security and web accessibility.

## 🔒 Security Features

- **Client-side AES encryption** with separate IV/salt for each secret
- **PBKDF2 key derivation** (15,000 iterations) for strong password protection
- **Zero-knowledge architecture** - server never sees unencrypted secrets
- **CSRF protection** on all forms
- **SQL injection prevention** with prepared statements
- **Session security** with HTTPOnly, Secure, and SameSite cookies
- **Input validation** and sanitization
- **Password verification** ensures login and encryption passwords match

## ✨ Features

- **TOTP Code Generation** - RFC 6238 compliant, 30-second refresh
- **Encrypted Storage** - Names and secrets encrypted separately
- **Export/Import** - Backup and restore your TOTP secrets
- **Modern UI** - Clean, responsive design with visual timer
- **Multi-Database** - Support for both SQLite and MySQL
- **Auto-Installation** - Automatic database and table creation
- **Registration Control** - Enable/disable new user registration

## 🚀 Quick Setup

### 1. Download Files
```bash
git clone <repository> otpx
cd otpx
```

### 2. Configure Database
Edit `config.php`:

**For SQLite (Recommended):**
```php
define('DB_TYPE', 'sqlite');
define('DB_SQLITE_PATH', '../otpx.sqlite'); // Outside web directory
```

**For MySQL:**
```php
define('DB_TYPE', 'mysql');
define('DB_HOST', 'localhost');
define('DB_NAME', 'totp_dashboard');
define('DB_USER', 'your_username');
define('DB_PASS', 'your_password');
```

### 3. Set Permissions (Important!)
```bash
# Set secure file permissions
chmod 644 *.php *.css *.js *.md
chmod 600 config.php

# For SQLite, secure the database file after first run
chmod 600 ../otpx.sqlite
```

### 4. Access Application
Navigate to `http://your-domain/otpx/` in your browser.

**No manual database setup required** - the application automatically creates all necessary tables and indexes.

## 📁 File Structure

```
otpx/
├── config.php          # Configuration and database functions
├── index.php           # Main dashboard
├── login.php           # User authentication
├── register.php        # User registration
├── logout.php          # Session termination
├── api.php             # AJAX endpoints
├── assets/
│   ├── style.css       # Modern UI styling
│   ├── script.js       # Client-side logic and encryption
│   └── crypto-js.min.js # Encryption library
└── README.md           # This file
```

## 🛠️ Configuration Options

### Security Settings (`config.php`)
```php
define('ALLOW_REGISTRATION', true);     // Enable/disable new registrations
define('SECURE_COOKIES', true);         // Require HTTPS for cookies
define('SESSION_LIFETIME', 3600);       // Session timeout (1 hour)
```

### Database Types
- **SQLite**: File-based, no server required, automatically secured
- **MySQL**: Traditional database server, supports clustering

## 💻 Usage

### Adding TOTP Secrets
1. **Login** with your credentials
2. **Enter password** to decrypt existing TOTPs
3. **Click "Add New TOTP"**
4. **Enter name** (e.g., "GitHub") and **Base32 secret key**
5. **Secret is encrypted** with your password before storage

### Viewing Codes
- **6-digit codes** refresh every 30 seconds
- **Visual timer** shows remaining time
- **Click code** to copy to clipboard
- **Red warning** when < 5 seconds remaining

### Export/Import
- **Export**: Download encrypted secrets as JSON backup
- **Import**: Restore from JSON backup file
- **Password required** for both operations

## 🔐 Security Model

### Encryption Flow
```
User Password → PBKDF2 (25k iterations) → AES-256 Key → Encrypt Secrets
```

### Data Protection
- **Names encrypted** with separate IV/salt
- **Secrets encrypted** with separate IV/salt  
- **Server storage** contains only encrypted data
- **Password verification** prevents data corruption

### Client-Side Security
- **No password storage** - entered fresh each session
- **Memory-only** encryption keys
- **TOTP generation** happens entirely in browser
- **Zero server trust** required for secret data

## 🛡️ Security Considerations

### Strengths
✅ **Zero-knowledge encryption** - server never sees secrets  
✅ **Strong cryptography** - AES-256 with PBKDF2  
✅ **Modern web security** - CSRF, XSS, SQLi protection  
✅ **Secure sessions** - Proper cookie configuration  

### Limitations
⚠️ **Client-side trust** - Vulnerable to browser compromise  
⚠️ **Password dependency** - Forgotten password = lost data  
⚠️ **No sync** - Local installation only  

### Best Practices
- **Use HTTPS** in production environments
- **Strong passwords** for user accounts
- **Regular backups** via export function
- **Secure hosting** with proper file permissions

## 🐛 Troubleshooting

### Database Issues
- **SQLite**: Ensure parent directory is writable
- **MySQL**: Verify credentials and server accessibility
- **Permissions**: Check file permissions (600 for sensitive files)

### PHP Requirements
- **PDO extension** with SQLite/MySQL driver
- **OpenSSL** for secure random number generation
- **Session support** enabled

### Common Errors
- **500 Error**: Check file permissions and PHP error logs
- **Database connection failed**: Verify database credentials
- **Invalid encrypted length**: Clear browser data and re-login

## 📋 Requirements

### Server Requirements
- **PHP 7.4+** with PDO extension
- **Web server** (Apache, Nginx, etc.)
- **SQLite** or **MySQL** database
- **HTTPS** recommended for production

### Browser Requirements
- **Modern browser** with JavaScript enabled
- **WebCrypto API** support (all modern browsers)
- **Local storage** for temporary session data

## 🔄 Updates

### Version History
- **v1.0**: Initial release with basic TOTP functionality
- **v1.1**: Added client-side encryption
- **v1.2**: Enhanced security audit and improvements
- **v1.3**: Auto-installation for both database types

### Upgrade Notes
- **Always backup** before upgrading
- **Check configuration** after updates
- **Review security settings** periodically

## 👥 Authors

- **@vaska94** - Project creator and developer
- **Claude** - AI assistant for development and security optimization

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. **Fork** the repository
2. **Create** a feature branch
3. **Commit** your changes
4. **Push** to the branch
5. **Submit** a pull request

## ⚠️ Disclaimer

This software is provided "as is" without warranty. Users are responsible for:
- **Secure deployment** and configuration
- **Regular backups** of TOTP secrets
- **Compliance** with applicable security standards

For production use, consider additional security measures such as:
- **Web Application Firewall (WAF)**
- **Rate limiting** and intrusion detection
- **Regular security audits** and penetration testing