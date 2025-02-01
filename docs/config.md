### **Explanation of the System Hardening Configuration**
This **YAML configuration file** defines the security policies for **automating system hardening**. It includes settings for **file permissions, SSH security, firewall rules, sysctl parameters, password policies, audit logging, service management, and security tools**.

---

## **1. File Permissions Hardening (`file_permissions`)**
This section ensures that critical system files have **proper ownership and permissions**:

| File | Permissions | Owner | Group | Purpose |
|---|---|---|---|---|
| `/etc/shadow` | `0400` (read-only for root) | `root` | `shadow` | Protects stored password hashes. |
| `/etc/passwd` | `0644` (readable by all, writable by root) | `root` | `root` | Contains user account information. |
| `/etc/group` | `0644` | `root` | `root` | Stores user group information. |
| `/etc/ssh/sshd_config` | `0600` | `root` | `root` | Controls SSH security settings. |
| `/etc/sudoers` | `0440` (read-only for root and group) | `root` | `root` | Defines sudo privileges. |

🔹 **Why?**  
Restricting access to these files prevents unauthorized modifications and reduces the risk of privilege escalation.

---

## **2. SSH Security Configuration (`ssh_config`)**
This section **controls SSH settings** to enhance security:

| Setting | Value | Purpose |
|---|---|---|
| `PermitRootLogin` | `"yes"` ❌ | **(Should be "no")** Prevents direct root login via SSH. |
| `PasswordAuthentication` | `"yes"` ❌ | **(Should be "no")** Disables password-based SSH login (use key-based auth). |
| `X11Forwarding` | `"no"` ✅ | Disables X11 forwarding to prevent GUI-related exploits. |
| `MaxAuthTries` | `"3"` ✅ | Limits authentication attempts to prevent brute-force attacks. |
| `Protocol` | `"2"` ✅ | Enforces SSH version 2 (more secure). |
| `PermitEmptyPasswords` | `"no"` ✅ | Prohibits empty passwords. |
| `ClientAliveInterval` | `"300"` ✅ | Disconnects inactive sessions after 5 minutes. |
| `ClientAliveCountMax` | `"3"` ✅ | Number of keep-alive messages before disconnecting. |
| `LogLevel` | `"VERBOSE"` ✅ | Enables detailed logging. |
| `Ciphers` | `"chacha20-poly1305@openssh.com,aes256-gcm@openssh.com"` ✅ | Enforces strong encryption ciphers. |
| `KexAlgorithms` | `"curve25519-sha256@libssh.org,diffie-hellman-group16-sha512"` ✅ | Uses strong key exchange algorithms. |
| `MACs` | `"hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"` ✅ | Enforces secure message authentication codes. |

🔹 **Why?**  
These settings **harden SSH security** by reducing brute-force risks, enforcing strong cryptographic settings, and logging all activities.

---

## **3. Firewall Configuration (`firewall`)**
This section **configures the Uncomplicated Firewall (UFW)** to restrict network traffic:

✅ **Default Policies:**
- `ufw default deny incoming` → Blocks all incoming traffic by default.
- `ufw default allow outgoing` → Allows all outgoing traffic.

✅ **Allowed Services:**
- `ufw allow ssh` → Allows SSH connections.
- `ufw allow http` → Allows web server access.
- `ufw allow https` → Allows secure web traffic.

❌ **Blocked (Denied) Services:**
- `ufw deny telnet` → Blocks insecure Telnet protocol.
- `ufw deny rsh` → Blocks Remote Shell service.
- `ufw deny rlogin` → Blocks Remote Login service.
- `ufw deny tftp` → Blocks Trivial File Transfer Protocol.

✅ **Other Firewall Settings:**
- `ufw logging on` → Enables firewall logging.
- `ufw --force enable` → Ensures UFW is activated.

🔹 **Why?**  
A **proper firewall configuration** prevents unauthorized network access while allowing necessary services.

---

## **4. Kernel Security Configuration (`sysctl`)**
This section **hardens network and kernel parameters** using `sysctl`.

✅ **Network Security:**
| Parameter | Value | Purpose |
|---|---|---|
| `net.ipv4.conf.all.accept_redirects` | `0` | Disables ICMP redirects (prevents MITM attacks). |
| `net.ipv4.conf.all.send_redirects` | `0` | Stops sending redirects to prevent network abuse. |
| `net.ipv4.conf.all.accept_source_route` | `0` | Prevents packet spoofing attacks. |
| `net.ipv4.conf.all.log_martians` | `1` | Logs suspicious packets (e.g., spoofed IPs). |
| `net.ipv4.icmp_echo_ignore_broadcasts` | `1` | Prevents smurf attack DDoS. |
| `net.ipv4.tcp_syncookies` | `1` | Protects against SYN flood attacks. |
| `net.ipv6.conf.all.disable_ipv6` | `1` | Disables IPv6 (if not in use). |

✅ **Kernel Security:**
- `kernel.randomize_va_space: "2"` → Enables **ASLR** (Address Space Layout Randomization).
- `kernel.sysrq: "0"` → Disables dangerous kernel debug commands.
- `fs.suid_dumpable: "0"` → Prevents core dumps from SUID programs (stops privilege escalation exploits).

🔹 **Why?**  
These **kernel and network protections** enhance **system security against various attacks**.

---

## **5. Password Policy Configuration (`password_policy`)**
This section **enforces strong passwords**.

✅ **Password Complexity Rules (pwquality.conf):**
- `minlen: 12` → Minimum 12-character password.
- `dcredit: -1`, `ucredit: -1`, `lcredit: -1`, `ocredit: -1` → Requires **uppercase, lowercase, digit, and special character**.
- `maxrepeat: 3` → Prevents repeating characters.
- `dictcheck: 1` → Checks against dictionary words.

✅ **Password Expiry Rules (login_defs):**
- `PASS_MAX_DAYS: 90` → Users must change passwords every **90 days**.
- `PASS_MIN_DAYS: 7` → Enforce a **minimum 7-day gap** between changes.
- `LOGIN_RETRIES: 3` → Lock accounts after **3 failed login attempts**.

🔹 **Why?**  
Prevents **brute-force attacks, weak passwords, and password reuse**.

---

## **6. Audit Logging Configuration (`audit_logging`)**
Defines **audit rules** to log critical system activities.

✅ **Monitored Files:**
- `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` → Logs access and modifications.

✅ **Monitored System Calls:**
- `execve` → Logs **executed commands**.
- `mount` → Logs **mount operations**.

✅ **Audit Log Settings:**
- `log_file: "/var/log/audit/audit.log"` → Stores logs.
- `max_log_file_action: "ROTATE"` → Rotates logs instead of deleting them.

🔹 **Why?**  
Audit logs help in **forensics, compliance, and detecting security incidents**.

---

## **7. Services Hardening (`services`)**
✅ **Disables Unnecessary Services:**
- `telnet`, `rsh`, `rpcbind`, `xinetd`, `cups`, `avahi-daemon` → Disables **unused and vulnerable** services.

✅ **Configures Secure NTP Servers:**
- Uses **0.pool.ntp.org**, **1.pool.ntp.org**, etc.
- Restricts access to the NTP service.

🔹 **Why?**  
Stops **legacy or unnecessary services** that might expose security vulnerabilities.

---

## **8. Security Tools Installation (`security_tools`)**
✅ **Installs Security Tools:**
- **Fail2Ban** → Blocks brute-force attacks.
- **AIDE** → Intrusion detection system.
- **rkhunter, chkrootkit** → Rootkit detection.
- **AppArmor** → Mandatory access control.
- **Unattended upgrades** → Automates security updates.

🔹 **Why?**  
Installing **security monitoring tools** helps **detect and prevent intrusions**.


