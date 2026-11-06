# AegisVault // CLI Command Reference & Operator Runbook

In alignment with **OWASP Control C5 (Secure By Default Configurations)** and the **Principle of Least Privilege**, administrative identity management in AegisVault is decoupled from the public web interface.

All operations execute through the Flask CLI harness using:
```powershell
flask --app run.py <command> [OPTIONS] [ARGS]
```

---

## 📋 Command Quick Reference

| Command | Category | Description | Example Syntax |
| :--- | :--- | :--- | :--- |
| **`create-admin`** | Provisioning | Provisions a root administrator account with Argon2id hashing. | `flask --app run.py create-admin <username>` |
| **`create-user`** | Provisioning | Provisions a standard user account directly via terminal. | `flask --app run.py create-user <username>` |
| **`reset-password`** | Credentials | Emergency password override for any account. | `flask --app run.py reset-password <username>` |
| **`change-role`** | Access Control | Promotes or demotes an operator (`user` or `admin`). | `flask --app run.py change-role <username> <admin\|user>` |
| **`list-users`** | Directory | Displays a formatted table of all registered accounts. | `flask --app run.py list-users` |
| **`deactivate-user`** | Lifecycle | Disables login without purging records or notes. | `flask --app run.py deactivate-user <username>` |
| **`activate-user`** | Lifecycle | Re-enables a deactivated account. | `flask --app run.py activate-user <username>` |
| **`delete-user`** | Lifecycle | Permanently removes an account and their vault records. | `flask --app run.py delete-user <username> [--yes]` |
| **`view-logs`** | SIEM / Audit | Displays recent security events (newest first). | `flask --app run.py view-logs [--limit 25]` |

---

## 1. Account Provisioning

### `create-admin <username>`
Creates a new administrator account with root clearance.
- **Security Control**: Prompts securely for password without terminal echo; requires confirmation; validates 8+ character minimum; hashes with Argon2id.
- **Audit Event**: Emits `CLI_USER_CREATED` to `logs/security.log`.

```powershell
flask --app run.py create-admin root_admin
# Password: [hidden]
# Repeat for confirmation: [hidden]
# [SUCCESS] Admin user 'root_admin' created successfully.
```

### `create-user <username>`
Creates a standard user account directly from the command line without visiting `/auth/register`.
- **Security Control**: Interactive password confirmation; Argon2id hashing; default role set to `user`.
- **Audit Event**: Emits `CLI_USER_CREATED` to `logs/security.log`.

```powershell
flask --app run.py create-user alice
# Password: [hidden]
# Repeat for confirmation: [hidden]
# [SUCCESS] User 'alice' created successfully.
```

---

## 2. Password & Role Management

### `reset-password <username>`
Provides an emergency credential reset mechanism if an operator loses their passphrase.
- **Security Control**: Non-echoing interactive prompt with confirmation; re-hashes with fresh Argon2id salt.
- **Audit Event**: Emits `CLI_PASSWORD_RESET` to `logs/security.log`.

```powershell
flask --app run.py reset-password alice
# New Password: [hidden]
# Repeat for confirmation: [hidden]
# [SUCCESS] Password for user 'alice' has been successfully reset.
```

### `change-role <username> <new_role>`
Promotes a user to `admin` or demotes an administrator to `user`.
- **Arguments**:
  - `username`: Operator handle
  - `new_role`: Either `user` or `admin`
- **Safety Guard**: **Last-Admin Preservation** prevents demoting the last active administrator, preventing administrative lockouts.
- **Audit Event**: Emits `CLI_ROLE_CHANGED` to `logs/security.log`.

```powershell
# Promote user to administrator
flask --app run.py change-role alice admin

# Demote user back to standard operator
flask --app run.py change-role alice user
```

---

## 3. Account Lifecycle & Directory

### `list-users`
Renders an ASCII table of all registered operators, their unique numeric IDs, role assignments, activation status, and registration UTC timestamps.

```powershell
flask --app run.py list-users
```

*Example Output:*
```text
-----------------------------------------------------------------
ID     USERNAME             ROLE       ACTIVE     REGISTERED UTC    
-----------------------------------------------------------------
#1     cliadmin             admin      YES        2026-11-05 12:27  
#2     arya                 user       YES        2026-11-05 12:32  
#3     secadmin             admin      YES        2026-11-05 13:42  
-----------------------------------------------------------------
Total users: 3
```

### `deactivate-user <username>`
Disables the account, preventing future web logins immediately while keeping notes and history intact.
- **Safety Guard**: Blocks deactivation of the last remaining active administrator.
- **Audit Event**: Emits `CLI_USER_DEACTIVATED` to `logs/security.log`.

```powershell
flask --app run.py deactivate-user arya
# [SUCCESS] User 'arya' has been deactivated.
```

### `activate-user <username>`
Reactivates a suspended user, restoring login capabilities immediately.
- **Audit Event**: Emits `CLI_USER_ACTIVATED` to `logs/security.log`.

```powershell
flask --app run.py activate-user arya
# [SUCCESS] User 'arya' has been activated.
```

### `delete-user <username> [--yes]`
Permanently purges an operator account and cascades deletion to all their stored vault records.
- **Flags**:
  - `--yes`: Skips the interactive confirmation prompt.
- **Safety Guard**: Blocks deletion of the last remaining administrator.
- **Audit Event**: Emits `CLI_USER_DELETED` to `logs/security.log`.

```powershell
# With confirmation prompt
flask --app run.py delete-user demo_user
# Are you sure you want to permanently delete user 'demo_user' and all their records? [y/N]: y
# [SUCCESS] User 'demo_user' and associated records have been deleted.

# Automated deletion
flask --app run.py delete-user demo_user --yes
```

---

## 4. SIEM Security Audit Log Inspection

### `view-logs [--limit N]`
Streams the latest security audit log entries from `logs/security.log` directly into the terminal, arranged in reverse-chronological order (newest activity first).
- **Options**:
  - `--limit INTEGER`: Number of latest events to display (default: 25).

```powershell
flask --app run.py view-logs --limit 10
```

*Example Output:*
```text
======================================================================
AEGISVAULT // SIEM AUDIT TRAIL (LATEST 5 EVENTS)
======================================================================
2026-11-05 23:31:16 [WARNING] [LOGIN_FAILED] Invalid credentials username=arya ip=127.0.0.1
2026-11-05 23:30:15 [WARNING] [SSRF_BLOCKED] url=http://127.0.0.1:8080/admin reason=Blocked IP 127.0.0.1 (loopback)
2026-11-05 23:30:02 [WARNING] [SSRF_BLOCKED] url=http://169.254.169.254/latest/meta-data/ reason=Blocked IP 169.254.169.254 (link-local)
2026-11-05 23:27:16 [INFO] [ROLE_CHANGED] Role for demo_admin changed from user to admin
2026-11-05 23:26:45 [INFO] [LOGIN_SUCCESS] User logged in username=demo_admin ip=127.0.0.1
======================================================================
```

---

## 5. Built-in Flask Commands

| Command | Purpose |
| :--- | :--- |
| **`flask --app run.py routes`** | Lists all registered HTTP route endpoints, methods, and URL rules. |
| **`flask --app run.py shell`** | Launches an interactive Python REPL pre-loaded with application context and database models (`User`, `Note`, `db`). |
