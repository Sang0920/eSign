# PDF eSigner Application

A comprehensive digital signature platform for PDF documents compliant with **PAdES (PDF Advanced Electronic Signatures)** standards. This application implements advanced cryptographic algorithms and security features for document authentication, integrity verification, and non-repudiation.

> **🌐 Live Demo**: [https://esign-odwx.onrender.com/](https://esign-odwx.onrender.com/)

> **Academic Project**: "Nghiên cứu về các giải thuật mã hóa và hàm băm để xây dựng ứng dụng chứng thực thông điệp" 
> (Research on encryption algorithms and hash functions to build message authentication applications)

> **Signature Validation**: Verify signed documents at [Vietnam National Electronic Authentication Center (NEAC)](https://neac.gov.vn/)

## 🚀 Key Features

### 🔐 **Advanced Security & Cryptography**
- **Multiple Hash Algorithms**: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512
- **RSA 2048-bit Encryption**: Secure key pair generation and digital signatures
- **X.509 Certificate Management**: Self-signed and CA-issued certificate support
- **Vietnam CA Integration**: Support for Vietnam National Root CA certificates

### 📱 **User Experience & Interface**
- **Responsive Web Design**: Bootstrap 5-based UI that works on all devices
- **Interactive PDF Viewer**: Multi-page PDF preview with tabbed interface
- **Visual Signature Creation**: Canvas-based signature drawing with save/reuse
- **Drag-and-Drop Positioning**: Precise signature placement with real-time coordinates

### 🔒 **Enterprise Security Features**
- **Two-Factor Authentication**: Re-authentication for sensitive operations
- **Certificate Validation**: Comprehensive certificate chain validation
- **Key Rotation System**: Automated key expiry monitoring and rotation
- **Admin Dashboard**: Certificate status monitoring for all users
- **Audit Trail**: Complete logging of all signature operations

### 📄 **Document Management**
- **Batch Processing**: Upload and manage multiple PDF documents
- **Secure Storage**: Encrypted file storage with user isolation
- **Search & Filter**: Advanced document filtering and pagination

## 📦 Installation & Setup

### **Local Development Setup**

1. **Clone and Setup**
   ```bash
   git clone https://github.com/sang0920/eSign.git
   cd eSign
   python -m venv .venv
   
   # Activate virtual environment
   # Windows: .venv\Scripts\activate
   # macOS/Linux: source .venv/bin/activate
   ```

2. **Install and Run**
   ```bash
   pip install -r requirements.txt
   cd esign-app
   pip install -r requirements.txt
   python fix_database_migration.py
   python app.py
   ```

3. **Access**: Open `http://127.0.0.1:5000` or use the live demo above

## 📸 Application Screenshots

### **Dashboard - Document Management**
![Dashboard](asset/screenshots/dashboard.png)
*Centralized document management with upload, status tracking, and quick actions*

### **Signature Creation**
![Signature Creation](asset/screenshots/signature%20creation%20page.png)
*Professional signature creation with HTML5 canvas and template management*

### **Document Signing Interface**
![Sign Page](asset/screenshots/sign%20page.png)
*Advanced signing interface with multi-page preview and precise positioning*

### **Certificate Validation**
![Certificate Validation](asset/screenshots/certificate%20validation%20page.png)
*Comprehensive certificate health monitoring and validation reports*

### **Key Rotation System**
![Key Status](asset/screenshots/key%20status%20page.png)
*Intelligent key rotation monitoring with risk assessment*

*[View all screenshots in asset/screenshots/ directory]*

## 🔬 Cryptographic Research Components

### **Educational Implementations**
- **Hash Functions**: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512 with demonstrations
- **Encryption**: AES-256-CBC, RSA encryption with key management
- **Digital Signatures**: Step-by-step signature creation and verification

### **Security Analysis Tools**
```bash
python main.py  # Run cryptographic demonstrations
# Choose option 2 for crypto demos
# Choose option 3 for OpenSSL operations
```

## 📊 Project Structure

```
eSign/
├── esign-app/                   # Main Flask application
│   ├── app.py                   # Application entry point
│   ├── models.py                # Database models
│   ├── templates/               # HTML templates
│   ├── static/css/style.css     # Custom styling
│   ├── utils/                   # Utility modules
│   │   ├── crypto.py            # Cryptographic functions
│   │   ├── pdf.py               # PDF processing
│   │   ├── security.py          # Security utilities
│   │   └── key_rotation.py      # Key management
│   ├── keys/                    # User key storage
│   ├── uploads/                 # Document storage
│   └── signatures/              # Signature images
├── asset/screenshots/           # Application screenshots
├── trust_store/                 # Certificate authority files
├── main.py                      # Cryptographic research demos
└── requirements.txt             # Dependencies
```

## 🔮 Future Enhancements

- [ ] Multi-language support (Vietnamese, English)
- [ ] Mobile application development
- [ ] Integration with external Certificate Authorities (VietSign, FPT-CA)
- [ ] API development for third-party integration
- [ ] Cloud storage integration
- [ ] Blockchain integration for audit trails

## 👨‍💻 Developer & Links

**Đỗ Thế Sang**
- **GitHub**: [@sang0920](https://github.com/sang0920)
- **Source Code**: [https://github.com/Sang0920/eSign](https://github.com/Sang0920/eSign)
- **Email**: dothesang20@gmail.com
- **Institution**: Ho Chi Minh University of Industry and Trade (HUIT)

### **Academic Context**
- **Course**: Advanced Cryptography and Information Security
- **Academic Year**: 2024-2025
- **Research Focus**: Practical implementation of digital signature standards

---

*This project demonstrates practical application of cryptographic algorithms in real-world software development, combining academic research with industry-standard security practices and Vietnamese digital signature compliance.*

