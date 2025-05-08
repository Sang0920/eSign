# PDF eSigner Application

A secure digital signature platform for PDF documents compliant with PAdES (PDF Advanced Electronic Signatures) standards. This application allows users to digitally sign PDF documents using cryptographic keys, ensuring document authenticity, integrity, and non-repudiation.

## Features

- 🔑 **Secure Authentication** - User registration and login system
- 📄 **Document Management** - Upload, view, and download PDF files
- ✍️ **Digital Signatures** - Sign PDFs with cryptographic signatures
- 🔐 **Multiple Hash Algorithms** - Support for SHA-256, SHA-384, SHA-512, SHA3-256, and SHA3-512
- 🖋️ **Visual Signatures** - Add visual signature elements to documents
- 📱 **Responsive Design** - Works on desktop and mobile devices
- 🌐 **Certificate Management** - Generate and manage X.509 certificates
- ⏱️ **Timestamp Support** - Add trusted timestamps to signatures

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/sang0920/eSign.git
   cd eSign
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows, use: .venv\Scripts\activate
   ```

3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up the database:
   ```bash
   cd esign-app
   python migrate_db.py
   ```

5. Start the application:
   ```bash
   python app.py
   ```

6. Access the application in your browser at `http://127.0.0.1:5000`

## Usage

### User Registration and Login
1. Create a new account with your email, name, and password
2. Log in with your credentials

### Managing Documents
1. Upload PDF documents from the dashboard
2. View the list of your uploaded documents
3. Sign, download, or view your documents

### Signing Documents
1. Select a document to sign from your dashboard
2. Create your signature using the signature pad
3. Position your signature on the document
4. Select the desired hash algorithm (SHA-256 recommended for most cases)
5. Click "Digitally Sign Document" to complete the process

### Cryptographic Features
The application provides multiple hash algorithms with different security levels:
- **SHA-256**: Standard security, widely compatible
- **SHA-384**: Enhanced security level
- **SHA-512**: Maximum security in the SHA-2 family
- **SHA3-256**: Modern algorithm with good compatibility
- **SHA3-512**: Maximum security, future-proof

## Technical Information

### Architecture
- **Frontend**: HTML, CSS, JavaScript, Bootstrap 5
- **Backend**: Python with Flask framework
- **Database**: SQLite
- **Cryptography**: RSA key pairs, X.509 certificates
- **PDF Processing**: PyMuPDF (fitz)

### Directory Structure
- esign-app: Main Flask application
  - app.py: Flask application entry point
  - models.py: Database models
  - `utils/`: Utility functions for cryptography and PDF operations
  - `templates/`: HTML templates
  - `static/`: CSS, JavaScript, and other assets
  - `keys/`: User key storage
- trust_store: Certificate authority and trusted certificates
- asset: Sample PDF documents and test files

### Security Features
- Password hashing and secure storage
- X.509 certificate-based signatures
- RSA 2048-bit key generation
- Multiple hash algorithm options
- Digital signature time-stamping

## Hash & MAC Utility

The repository also includes a command-line utility (`hash_mac_cli.py`) for demonstrating hash functions and message authentication codes:

```bash
python hash_mac_cli.py
```

## License

This project is released under the MIT License.

## Developer

Developed by Đỗ Thế Sang ([github.com/sang0920](https://github.com/sang0920))

For questions or support, please contact: dothesang20@gmail.com