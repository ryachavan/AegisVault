# AEGIS//VAULT: Zero-Trust Security Enclave

> **A defense-in-depth, hardened local vault application built to demonstrate the practical implementation of all 10 OWASP Proactive Controls.**  
> Designed for high-consequence environments where conventional web tools introduce unacceptable attack surfaces.  
> Official OWASP Top 10 Reference: [https://top10.owasp.org/](https://top10.owasp.org/)

---

## 🛡️ Architectural Overview (C1–C10 Defense-in-Depth)

AegisVault maps directly to the **OWASP Top 10 Proactive Controls**:

| Control | Name | Implementation in AegisVault | Neutralized Threats |
| :--- | :--- | :--- | :--- |
| **C1** | **Implement Access Control** | Global `before_request` deny-by-default, `@owner_required` (404 parity), `@role_required("admin")`, and last-admin demotion prevention. | Insecure Direct Object References (IDOR), horizontal privilege escalation, administrative lockouts. |
| **C2** | **Use Cryptography to Protect Data** | Argon2id password hashing (`argon2-cffi`), automatic re-hashing on login, and strict assertion of a 256-bit cryptographically secure `SECRET_KEY`. | Offline credential cracking, rainbow tables, weak session tokens. |
| **C3** | **Validate all Input & Handle Exceptions** | WTForms strict allowlists, SQLAlchemy parameterized queries, and custom error handlers (403, 404, 500) suppressing stack traces. | SQL Injection (SQLi), Cross-Site Scripting (XSS), debug information leakage. |
| **C4** | **Address Security from the Start** | STRIDE threat model ([`docs/threat-model.md`](docs/threat-model.md)) and full traceability matrix ([`docs/controls-map.md`](docs/controls-map.md)). | Security architectural blindness, unmodeled trust boundary violations. |
| **C5** | **Secure By Default Configurations** | `DEBUG=False` by default, admin creation restricted strictly to CLI (`flask create-admin`), and principle of least privilege. | Misconfigured debug execution, unauthorized administrative self-registration. |
| **C6** | **Keep your Components Secure** | Pinned dependencies in `requirements.txt` with continuous vulnerability auditing via `pip-audit` (0 known CVEs). | Supply-chain attacks, vulnerable transitive third-party dependencies. |
| **C7** | **Secure Digital Identities** | Flask-Limiter brute-force throttling (5/min), session rotation on login (`session.clear()`), 30-min idle timeout, and anti-cache headers. | Automated credential stuffing, session fixation, browser history/bfcache leakage. |
| **C8** | **Leverage Browser Security Features** | Flask-Talisman strict CSP (`script-src 'self'`, no `unsafe-inline`), secure cookie flags (`HttpOnly`, `SameSite=Lax`, `Secure`), and CSRF tokens on all POSTs. | Stored/Reflected XSS, Cross-Site Request Forgery (CSRF), clickjacking. |
| **C9** | **Implement Security Logging and Monitoring** | Structured security logging with Python's `RotatingFileHandler` (1 MB, 5 backups) and a reverse-chronological admin SIEM dashboard. | Undetected intrusion, insider abuse, lack of forensic auditability. |
| **C10** | **Stop Server Side Request Forgery (SSRF)** | Dedicated SSRF gateway resolving DNS, blocking loopback, link-local, and RFC 1918 subnets, socket pinning against DNS rebinding, 1 MB stream cap. | Cloud metadata theft (`169.254.169.254`), internal network pivoting, host file exfiltration. |

---

## 📂 File Structure & Purpose

```text
secure-notes/
├── app/
│   ├── blueprints/           # auth, notes (vault CRUD), and admin routes
│   ├── security/             # Core security implementations:
│   │   ├── ssrf.py           # Anti-SSRF gateway with DNS pinning & IP blocklists
│   │   ├── passwords.py      # Argon2id password hashing & verification
│   │   ├── decorators.py     # @owner_required (anti-IDOR 404 parity) & @role_required
│   │   └── logging_setup.py  # Structured SIEM logging with rotating file handler
│   ├── static/               # External CSS (strict CSP compliant, no inline styles)
│   ├── templates/            # Jinja2 HTML templates
│   ├── __init__.py           # Application factory & security headers middleware
│   ├── cli.py                # Admin CLI commands (create-admin, reset-password)
│   ├── config.py             # Environment configurations (Dev, Prod, Test)
│   └── models.py             # SQLAlchemy models (User, Note)
├── docs/
│   ├── cli-commands.md       # Full CLI command reference & operator runbook
│   ├── controls-map.md       # OWASP Top 10 Proactive Controls traceability matrix
│   └── threat-model.md       # STRIDE threat model & data flow diagrams
├── instance/
│   └── secure_notes.db       # Local SQLite database (gitignored)
├── logs/
│   └── security.log          # Security audit event log (gitignored)
├── tests/                    # Automated pytest suite (49 security & functional tests)
├── .env.example              # Environment variable template
├── .gitignore                # Excludes secrets, database, logs, and caches
├── pytest.ini                # Pytest configuration
├── requirements.txt          # Pinned & audited dependencies
└── run.py                    # Application entry point
```

---

## 🚀 Quick Start & Installation

### Prerequisites
- Python 3.10, 3.11, or 3.12
- Git

### 1. Clone & Set Up Virtual Environment
```powershell
# Clone repository
git clone <repository_url>
cd secure-notes

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 2. Install Audited Dependencies
```powershell
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Create your local `.env` configuration file from the template:
```powershell
Copy-Item .env.example .env
```
Ensure `.env` contains a strong 256-bit secret key (generate with `python -c "import secrets; print(secrets.token_hex(32))"`):
```ini
FLASK_ENV=development
SECRET_KEY=949319feeb61d50cbe441a1d95dc55e2e8e7aeb29cb40a8d6fb7247a82c40cba
DATABASE_URL=sqlite:///instance/secure_notes.db
```

### 4. Initialize Database & Create Initial Admin
In accordance with **Control C5 (Secure Defaults)**, administrative accounts cannot be registered via the web interface. Initialize the root administrator via CLI:
```powershell
flask --app run.py create-admin --username secadmin --password "SecAdminPass123!"
```

### 5. Launch Application
```powershell
python run.py
```
Open **[http://127.0.0.1:5000](http://127.0.0.1:5000)** in your browser. The zero-trust home landing page will greet you with the full interactive OWASP control architecture.

---

## 🧪 Security Validation & Testing

AegisVault includes a comprehensive test suite covering all 10 controls:

### Run Automated Tests (Pytest)
```powershell
pytest -v
```
*Expected Output: `49 passed in 3.0s`*

### Run Dependency Vulnerability Audit
```powershell
pip-audit -r requirements.txt
```
*Expected Output: `No known vulnerabilities found`*

---

## 📚 References & Standards
- **OWASP Top 10 Web Application Vulnerabilities**: [https://top10.owasp.org/](https://top10.owasp.org/)
- **OWASP Proactive Controls (C1–C10)**: [https://owasp.org/www-project-proactive-controls/](https://owasp.org/www-project-proactive-controls/)
- **CLI Command Reference**: [`docs/cli-commands.md`](docs/cli-commands.md)
- **STRIDE Threat Modeling Guide**: [`docs/threat-model.md`](docs/threat-model.md)
- **Controls Traceability Matrix**: [`docs/controls-map.md`](docs/controls-map.md)
