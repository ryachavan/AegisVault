# STRIDE Threat Model: AegisVault

**Control Reference**: C4 (Address Security from the Start)  
**Methodology**: Microsoft STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)  
**Architecture Context**: Flask application with SQLite/SQLAlchemy ORM, Flask-Login, Flask-WTF, Flask-Talisman, Flask-Limiter, and Argon2id.

---

## 1. System Overview & Asset Inventory

### Assets
1. **User Credentials & Identity Tokens**: Argon2 password hashes, session cookies, CSRF tokens.
2. **User Notes Content**: Confidential personal text notes, titles, attached URL metadata.
3. **Internal Network Perimeter**: Loopback interfaces (`127.0.0.1`, `::1`), private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), cloud metadata services (`169.254.169.254`).
4. **Audit Logs & System Integrity**: `logs/security.log`, database tables (`users`, `notes`).

### Trust Boundaries
- **Boundary 1 (Client <-> Application)**: Untrusted browser requests communicating with the Flask backend over HTTP/HTTPS.
- **Boundary 2 (Application <-> Database)**: Application server querying the SQLite database file via SQLAlchemy ORM.
- **Boundary 3 (Application <-> External Internet)**: Link preview service fetching remote web pages on behalf of users.
- **Boundary 4 (Authorization Clearances)**: Unauthenticated visitor vs. Authenticated User vs. Root Admin.

---

## 2. STRIDE Threat Analysis Matrix

| Threat Category | Asset / Target | Threat Scenario | Impact | Mitigation / Implemented Control | Verified By Test |
|---|---|---|---|---|---|
| **Spoofing** | User Identity / Login | Attacker guesses weak user passwords via brute-force or credential stuffing. | Account takeover, unauthorized vault access. | **C7**: Argon2id slow hashing (`passwords.py`), login rate limit of 5/min on POST (`auth.py`). Generic "Invalid credentials" response. | `tests/test_rate_limit.py::test_c7_login_rate_limit_triggers` |
| **Spoofing** | Session Cookie | Attacker intercepts or predicts session identifiers. | Session hijacking. | **C7, C8**: Session regenerated via `session.clear()` on login; `HttpOnly`, `SameSite=Lax`, 30-min idle timeout. `Secure` flag enabled in `ProdConfig`. | `tests/test_session.py::test_c7_session_regenerated_on_login`, `tests/test_headers.py::test_c8_cookie_flags_httponly_samesite` |
| **Spoofing** | State-changing Actions | Cross-Site Request Forgery (CSRF) tricking a user into deleting notes or modifying roles. | Unauthorized deletion or role modification. | **C8**: Flask-WTF `CSRFProtect` globally active. Every state-changing form (note deletion, role change, logout) requires a valid CSRF token. | `tests/test_csrf.py::test_c8_post_without_csrf_token_rejected` |
| **Tampering** | Database / SQL Queries | Attacker injects SQL payloads (`' OR 1=1--`) into login or note forms. | Database extraction or corruption. | **C3**: 100% ORM-only queries via SQLAlchemy. Parameterized queries used exclusively; no string-concatenated SQL queries exist in codebase. | `tests/test_sqli.py::test_c3_sqli_payload_in_login_neutralised`, `tests/test_sqli.py::test_c3_sqli_payload_in_note_creation_neutralised` |
| **Tampering** | DOM / Web Content | Stored XSS via `<script>alert(1)</script>` or malicious HTML in note title, body, or URL preview. | Client-side script execution, token theft. | **C3, C8**: Jinja2 automatic HTML escaping enabled by default. Flask-Talisman CSP enforces `default-src 'self'`, `script-src 'self'`, forbidding `unsafe-inline`. | `tests/test_xss.py::test_c3_xss_script_tags_escaped_in_note_view`, `tests/test_headers.py::test_c8_security_headers_present_in_dev` |
| **Repudiation** | Security Incidents | Attacker attempts unauthorized actions or SSRF exploits, denying actions occurred. | Inability to audit or attribute malicious activity. | **C9**: Dedicated `RotatingFileHandler` writing structured events for `LOGIN_SUCCESS`, `LOGIN_FAILED`, `ACCESS_DENIED`, `ROLE_CHANGED`, and `SSRF_BLOCKED`. Log viewing restricted to admin. | `tests/test_logging.py::test_c9_failed_login_logged`, `tests/test_logging.py::test_c9_ssrf_blocked_logged` |
| **Information Disclosure** | Cross-User Note Access | User A changes the URL ID (`/notes/2`) to view or edit User B's private notes (IDOR). | Privacy breach, confidential data leak. | **C1**: `@owner_required` decorator validates note ownership against `current_user.id`. Missing and unowned notes return identical generic 404 responses to prevent note enumeration. | `tests/test_authz.py::test_c1_user_cannot_read_another_users_note`, `tests/test_authz.py::test_c1_user_cannot_edit_another_users_note` |
| **Information Disclosure** | Internal Network Services | SSRF via note link preview fetching `http://169.254.169.254` (cloud metadata) or `http://127.0.0.1:6379` (internal Redis). | Cloud credential theft, internal service compromise. | **C10**: `safe_fetch_url()` resolves DNS, checks all IP addresses against loopback/private/link-local/multicast ranges, pins connection to vetted IP, disables redirects, caps response at 1 MB, 5s timeout. | `tests/test_ssrf.py::test_c10_blocks_loopback_ipv4`, `tests/test_ssrf.py::test_c10_blocks_cloud_metadata_ip`, `tests/test_ssrf.py::test_c10_blocks_private_network_10_x` |
| **Information Disclosure** | Stack Traces & Debugging | Application errors expose internal file paths, framework versions, or database structure. | Reconnaissance data leak to attacker. | **C3, C5**: `DEBUG = False` default in all configurations. Custom generic error templates for 403, 404, and 500 without stack traces or sensitive data. | `tests/test_c3_generic_error_pages` |
| **Denial of Service** | Application Availability | Attacker floods login or registration endpoints with high-volume requests. | Service disruption, authentication failure for legitimate users. | **C7**: Flask-Limiter enforces rate limit (`5 per minute` per client IP on POST). | `tests/test_rate_limit.py::test_c7_login_rate_limit_triggers` |
| **Denial of Service** | SSRF Stream Exhaustion | Attacker inputs a URL pointing to a multi-gigabyte file or slow-drip server. | Server thread exhaustion, disk/memory overflow. | **C10**: Enforces strict 5-second socket timeout, 1 MB maximum response size cap with streaming consumption, and requires `text/html` Content-Type. | `tests/test_ssrf.py::test_c10_blocks_redirects` |
| **Elevation of Privilege** | Administrative Controls | Regular authenticated user attempts to access `/admin/users` or `/admin/logs`. | Unauthorized clearance promotion, audit trail viewing. | **C1**: `@role_required("admin")` decorator aborts with 403 Forbidden. Global `before_request` enforces deny-by-default login requirement. | `tests/test_authz.py::test_c1_non_admin_cannot_access_admin_routes` |
| **Elevation of Privilege** | Admin Lockout / Hostile Demotion | Malicious admin demotes the last remaining administrator, locking everyone out of administrative controls. | Total administrative denial-of-service. | **C1**: `change_role` checks `admin_count`. Prevents demotion if only 1 admin remains. | `tests/test_authz.py::test_c1_cannot_remove_last_admin` |

---

## 3. Data Flow Diagram & Boundaries

```
[ Untrusted Client / Browser ]
           │
           │ (HTTPS / TLS, Secure Cookies, CSRF, CSP)
           ▼
[ Flask Application Perimeter ]
   ├── before_request: C1 Deny-by-Default (Redirect unauthenticated to /auth/login)
   ├── C8 Talisman: CSP (No unsafe-inline), X-Frame-Options (DENY), HSTS
   ├── C7 Limiter: 5/min rate limit on login/register POST
   │
   ├── Blueprints:
   │    ├── auth_bp: Argon2id verification, session regeneration (C2, C7)
   │    ├── notes_bp: @owner_required decorator, ORM queries (C1, C3)
   │    └── admin_bp: @role_required("admin"), last-admin lock (C1, C9)
   │
   ├── Security Subsystems:
   │    ├── security/passwords.py (Argon2id hashing & automatic rehash)
   │    ├── security/ssrf.py (DNS resolution, IP filtering, DNS pinning, 1MB limit)
   │    └── security/logging_setup.py (Rotating file logger, event structure)
   │
   ├── SQLite Database (users, notes) ── via SQLAlchemy ORM (C3)
   └── External Web (Link Preview) ── vetted via anti-SSRF gateway (C10)
```
