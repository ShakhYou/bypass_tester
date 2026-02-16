# 🔓 Access Control Bypass Tester

A powerful Python tool for testing access control vulnerabilities through 140+ bypass techniques including path manipulation, header injection, HTTP verb tampering, and protocol confusion attacks.

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

## 🎯 Features

- **140+ Bypass Techniques**: Path traversal, encoding tricks, header manipulation
- **Multi-threaded**: Fast concurrent testing (configurable threads)
- **Custom Headers**: Add your own authentication/API headers
- **Header Combinations**: Test multiple headers together for complex bypasses
- **HTTP Verb Tampering**: Automatic method switching (GET→HEAD, POST→PUT, etc.)
- **Body-Based Bypasses**: JSON payload testing for POST/PUT/PATCH requests
- **Smart Detection**: Identifies IP spoofing, URL rewrite, and method override bypasses
- **Comprehensive Logging**: Detailed output with success tracking

## 📥 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/bypass-tester.git
cd bypass-tester

# Install dependencies
pip install requests

# Run the tool
python3 bypass_tester.py -u https://target.com/admin
```

## 🚀 Quick Start

### Basic Usage
```bash
python3 bypass_tester.py -u https://api.example.com/admin
```

### With Custom Headers
```bash
python3 bypass_tester.py -u https://api.example.com/admin \
    -H "Authorization: Bearer token123" \
    -H "X-API-Key: secret"
```

### Fast Scan (More Threads)
```bash
python3 bypass_tester.py -u https://example.com/api -t 20
```

### Verbose Output
```bash
python3 bypass_tester.py -u https://example.com/admin -v
```

## 📖 Usage

```
usage: bypass_tester.py [-h] -u URL [-H HEADERS] [-t THREADS] [--timeout TIMEOUT] [-v]

Access Control Bypass Testing Tool

options:
  -h, --help            Show this help message and exit
  -u URL, --url URL     Target URL to test (required)
  -H HEADERS, --header HEADERS
                        Custom header (format: 'Key: Value'). Can be used multiple times
  -t THREADS, --threads THREADS
                        Number of concurrent threads (default: 10)
  --timeout TIMEOUT     Request timeout in seconds (default: 5)
  -v, --verbose         Verbose output - show all requests
```

## 🔥 Bypass Techniques

### Path Manipulation
- Path traversal (`/admin/../admin`, `/admin/..;/`)
- Encoding variations (`/%61dmin`, `%252fadmin`)
- Case mutations (`/Admin`, `/ADMIN`)
- Unicode normalization

### Header-Based Bypasses
- IP Spoofing (`X-Forwarded-For: 127.0.0.1`)
- URL Rewriting (`X-Original-URL: /admin`)
- Method Override (`X-HTTP-Method-Override: GET`)
- Multi-header combinations

### HTTP Method Tampering
- Verb switching (GET→HEAD, POST→PUT)
- Method tunneling via headers
- TRACE, CONNECT testing

### Advanced Techniques
- HTTP request smuggling patterns
- Protocol confusion attacks
- Body-based bypasses (JSON payloads)
- Cache poisoning headers
- CDN-specific bypasses

**See [BYPASS_TECHNIQUES.md](BYPASS_TECHNIQUES.md) for complete documentation.**

## 📊 Example Output

```
[*] Target: https://api.example.com/admin
[*] Threads: 10
[*] Testing 350 path variations × 9 methods
────────────────────────────────────────────────────────────────────────────────
METHOD   | CODE  | LENGTH   | PATH
────────────────────────────────────────────────────────────────────────────────
GET      | 403   | 1234     | /admin
GET      | 200   | 5678     | /admin/
  [!] BYPASS: X-Forwarded-For: 127.0.0.1 → 200
  [!!] COMBO BYPASS: X-Real-IP: 127.0.0.1, X-Forwarded-Proto: https → 200
HEAD     | 200   | 0        | /admin
  [!] VERB TAMPERING: GET → HEAD → 200

════════════════════════════════════════════════════════════════════════════════
                              BYPASS SUMMARY
════════════════════════════════════════════════════════════════════════════════
[+] Found 3 potential bypass(es):

  1. SUCCESS: GET /admin/ (Status: 200)
  2. HEADER BYPASS: GET /admin via X-Forwarded-For: 127.0.0.1 (Status: 200)
  3. VERB TAMPERING: /admin GET→HEAD (Status: 200)
════════════════════════════════════════════════════════════════════════════════
```

## 🎓 Real-World Examples

### Test Admin Panel
```bash
python3 bypass_tester.py -u https://example.com/admin -t 15
```

### Test API Endpoint with Authentication
```bash
python3 bypass_tester.py -u https://api.example.com/users \
    -H "Authorization: Bearer eyJ..." \
    -H "X-API-Key: abc123" \
    -t 10
```

### Stealth Mode (Slow, Avoid Detection)
```bash
python3 bypass_tester.py -u https://target.com/internal \
    -t 3 --timeout 10
```

## ⚠️ Legal Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

This tool is designed for security professionals to test systems they have explicit permission to test. Unauthorized access to computer systems is illegal.

- ✅ Use only on systems you own or have written permission to test
- ✅ Ensure you have proper authorization and scope documentation
- ✅ Follow responsible disclosure practices
- ❌ Do not use for malicious purposes
- ❌ Do not test systems without authorization

**The authors are not responsible for misuse of this tool.**

## 🛡️ Responsible Usage

1. **Get Permission**: Always obtain written authorization before testing
2. **Respect Scope**: Only test approved targets and endpoints
3. **Rate Limiting**: Use fewer threads (`-t 5`) for production systems
4. **Document Findings**: Keep detailed records of discovered bypasses
5. **Report Properly**: Follow responsible disclosure guidelines

## 📚 Documentation

- **[BYPASS_TECHNIQUES.md](BYPASS_TECHNIQUES.md)** - Detailed explanation of all 140+ bypass techniques
- **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - Quick cheat sheet for common bypasses
- **[OPTIMIZATION_SUMMARY.md](OPTIMIZATION_SUMMARY.md)** - Performance improvements and features

## 🔧 Requirements

- Python 3.7+
- `requests` library

```bash
pip install requests
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- OWASP Testing Guide
- PortSwigger Web Security Academy
- Bug bounty community research
- Security researchers worldwide

## 📞 Contact

For questions or security concerns, please open an issue on GitHub.

---

**⭐ If you find this tool useful, please consider giving it a star!**

## 🔗 Resources

- [OWASP Access Control Testing](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Academy](https://portswigger.net/web-security)
- [HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [HackerOne Reports](https://hackerone.com/hacktivity)

---

**Made with ❤️ for the security community**
