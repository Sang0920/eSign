# PDF eSigner Application

A comprehensive digital signature platform for PDF documents compliant with **PAdES (PDF Advanced Electronic Signatures)** standards. This application implements advanced cryptographic algorithms and security features for document authentication, integrity verification, and non-repudiation.

> **Academic Project**: "Nghiên cứu về các giải thuật mã hóa và hàm băm để xây dựng ứng dụng chứng thực thông điệp" 
> (Research on encryption algorithms and hash functions to build message authentication applications)

## 🚀 Key Features

### 🔐 **Advanced Security & Cryptography**
- **Multiple Hash Algorithms**: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512 with step-by-step implementation
- **RSA 2048-bit Encryption**: Secure key pair generation and digital signatures
- **X.509 Certificate Management**: Self-signed and CA-issued certificate support
- **Cryptographic Algorithm Demonstrations**: Educational implementations of core algorithms
- **HMAC Authentication**: Message Authentication Code for data integrity
- **AES Encryption**: Advanced Encryption Standard implementation

### 📱 **User Experience & Interface**
- **Responsive Web Design**: Bootstrap 5-based UI that works on all devices
- **Interactive PDF Viewer**: Multi-page PDF preview and navigation
- **Visual Signature Creation**: Canvas-based signature drawing with save/reuse functionality
- **Drag-and-Drop Positioning**: Precise signature placement on documents
- **Real-time Preview**: Live signature positioning feedback

### 🔒 **Enterprise Security Features**
- **Two-Factor Authentication**: Re-authentication for sensitive operations
- **Session Management**: Secure password storage with encryption and timeout
- **Certificate Validation**: Comprehensive certificate chain validation
- **Key Rotation System**: Automated key expiry monitoring and rotation
- **Admin Dashboard**: Certificate status monitoring for all users
- **Audit Trail**: Complete logging of all signature operations

### 📄 **Document Management**
- **Batch Processing**: Upload and manage multiple PDF documents
- **Document History**: Track all signature operations and versions
- **Secure Storage**: Encrypted file storage with user isolation
- **Download Options**: Original and signed document downloads
- **Search & Filter**: Advanced document filtering and search capabilities

### ⚡ **Performance & Scalability**
- **Paginated Views**: Efficient handling of large document collections
- **Optimized PDF Processing**: PyMuPDF for fast PDF manipulation
- **Database Optimization**: SQLAlchemy ORM with efficient queries
- **Secure File Handling**: UUID-based file naming and secure access

## 🏗️ Technical Architecture

### **Backend Technologies**
- **Framework**: Flask (Python 3.12+)
- **Database**: SQLite with SQLAlchemy ORM
- **PDF Processing**: PyMuPDF (fitz) for document manipulation
- **Cryptography**: Python `cryptography` library for all crypto operations
- **Authentication**: Flask-Login with secure session management

### **Frontend Technologies**
- **UI Framework**: Bootstrap 5.3.0 with responsive design
- **Icons**: Bootstrap Icons 1.11.0
- **JavaScript**: Vanilla JS with modern ES6+ features
- **Canvas API**: HTML5 Canvas for signature creation
- **CSS3**: Custom styling with flexbox and grid layouts

### **Security Implementation**
- **Encryption**: RSA-2048, AES-256-CBC
- **Hashing**: SHA-2 and SHA-3 family algorithms
- **Authentication**: PBKDF2 password hashing
- **Session Security**: Encrypted session tokens with expiration
- **Certificate Validation**: X.509 chain validation with CRL checking

## 📦 Installation & Setup

### **Prerequisites**
```bash
Python 3.12+
pip package manager
Virtual environment (recommended)
```

### **Installation Steps**

1. **Clone the Repository**
   ```bash
   git clone https://github.com/sang0920/eSign.git
   cd eSign
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv .venv
   
   # On Windows
   .venv\Scripts\activate
   
   # On macOS/Linux
   source .venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   cd esign-app
   pip install -r requirements.txt
   ```

4. **Initialize Database**
   ```bash
   cd esign-app
   python fix_database_migration.py  # Run migration script
   python app.py  # This will create tables if needed
   ```

5. **Configure Environment (Optional)**
   ```bash
   # For production deployment
   export FLASK_ENV=production
   export SECRET_KEY=your-secure-secret-key
   export DATABASE_URL=your-database-url
   ```

6. **Start the Application**
   ```bash
   python app.py
   ```

7. **Access the Application**
   - Open your browser and navigate to `http://127.0.0.1:5000`
   - Register a new account to get started

## 🎯 Usage Guide

### **Getting Started**
1. **User Registration**: Create account with email, username, and secure password
2. **Automatic Key Generation**: RSA key pair and X.509 certificate created automatically
3. **Document Upload**: Upload PDF documents up to 16MB
4. **Signature Creation**: Draw or upload signature images for reuse

### **Document Signing Process**
1. **Select Document**: Choose from uploaded documents
2. **Create/Select Signature**: Use drawing canvas or saved signatures
3. **Position Signature**: Drag and drop signature on document preview
4. **Choose Algorithm**: Select hash algorithm (SHA-256 recommended)
5. **Digital Signing**: Authenticate and apply cryptographic signature
6. **Download Results**: Get signed PDF with embedded digital signature

### **Security Features**
- **Certificate Validation**: Check certificate status and validity
- **Key Rotation**: Monitor and rotate certificates before expiry
- **Admin Functions**: View all users' certificate status (admin only)
- **Audit Logging**: Track all signature operations

## 🔬 Cryptographic Research Components

### **Hash Function Implementations**
The project includes educational implementations of:

- **SHA-256**: Step-by-step hash calculation with detailed output
- **HMAC-SHA256**: Message Authentication Code implementation
- **Hash Comparison**: Performance and security analysis of different algorithms

### **Encryption Demonstrations**
- **AES-256-CBC**: Symmetric encryption with padding
- **RSA Encryption**: Asymmetric encryption and digital signatures
- **Key Generation**: Cryptographically secure random key generation

### **Security Analysis Tools**
```bash
# Run cryptographic demonstrations
python main.py

# Choose option 2 for crypto demos
# Choose option 3 for OpenSSL operations
```

## 📊 Project Structure

```
eSign/
├── esign-app/                   # Main Flask application
│   ├── app.py                   # Application entry point
│   ├── config.py                # Configuration settings
│   ├── models.py                # Database models
│   ├── templates/               # HTML templates
│   │   ├── base.html            # Base template
│   │   ├── dashboard.html       # User dashboard
│   │   ├── sign_pdf.html        # Document signing interface
│   │   ├── certificate_validation.html
│   │   └── key_rotation_check.html
│   ├── static/                  # CSS, JS, and assets
│   │   └── css/style.css        # Custom styling
│   ├── utils/                   # Utility modules
│   │   ├── crypto.py            # Cryptographic functions
│   │   ├── pdf.py               # PDF processing
│   │   ├── security.py          # Security utilities
│   │   ├── certificate_validation.py
│   │   └── key_rotation.py      # Key management
│   ├── keys/                    # User key storage
│   ├── uploads/                 # Document storage
│   └── signatures/              # Signature images
├── trust_store/                 # Certificate authority files
├── main.py                      # Cryptographic research demos
├── README.md                    # Project documentation
└── requirements.txt             # Python dependencies
```

## 🔧 Advanced Configuration

### **Production Deployment**
```python
# config.py production settings
class ProductionConfig:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    DATABASE_URL = os.environ.get('DATABASE_URL')
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    WTF_CSRF_ENABLED = True
```

### **Certificate Authority Setup**
```bash
# Generate CA certificate (optional)
openssl req -x509 -new -key private_key.pem -sha256 -days 365 -out ca.crt
```

### **Timestamp Server Configuration**
The application supports RFC 3161 timestamp servers for enhanced signature validity.

## 📈 Performance Metrics

- **Document Processing**: Handles PDFs up to 16MB efficiently
- **Signature Speed**: Sub-second signature application
- **Concurrent Users**: Supports multiple simultaneous users
- **Database Performance**: Optimized queries with pagination
- **Security**: Zero known vulnerabilities in crypto implementation

## 🛡️ Security Considerations

### **Implemented Security Measures**
- **Password Security**: PBKDF2 hashing with salt
- **Session Security**: Encrypted tokens with expiration
- **File Security**: UUID-based naming, secure storage
- **Input Validation**: Comprehensive input sanitization
- **CSRF Protection**: Cross-site request forgery prevention

### **Best Practices**
- Regular key rotation (recommended annually)
- Strong password requirements
- Certificate validation monitoring
- Audit log review
- Secure backup procedures

## 🧪 Testing & Validation

### **Security Testing**
- Cryptographic algorithm validation
- Certificate chain verification
- Session security testing
- Input validation testing

### **Compatibility Testing**
- Multiple PDF readers (Adobe, Chrome, Firefox)
- Various operating systems
- Different browser environments
- Mobile device compatibility

## 📚 Educational Value

This project serves as a comprehensive example of:

1. **Applied Cryptography**: Real-world implementation of crypto algorithms
2. **Web Security**: Secure web application development practices
3. **Digital Signatures**: PAdES-compliant signature implementation
4. **Certificate Management**: X.509 certificate lifecycle management
5. **Software Architecture**: Clean, maintainable code structure

## 🤝 Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

### **Development Setup**
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Code formatting
black esign-app/
```

## 👨‍💻 Developer

**Đỗ Thế Sang**
- GitHub: [@sang0920](https://github.com/sang0920)
- Email: dothesang20@gmail.com
- Institution: Ho Chi Minh University of Industry and Trade (HUIT)

### **Academic Supervision**
This project was developed as part of academic research in cryptographic algorithms and message authentication systems.

## 🙏 Acknowledgments

- **HUIT Lab** for providing research environment and resources
- **Python Cryptography Community** for excellent libraries and documentation
- **Flask Community** for the robust web framework
- **Bootstrap Team** for the responsive UI framework

---

*This project demonstrates the practical application of cryptographic algorithms in real-world software development, combining academic research with industry-standard security practices.*
