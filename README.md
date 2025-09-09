# Juice Shop Lab Console (Streamlit)

This project is a **Streamlit-based security lab console** built to demonstrate three key web vulnerabilities using the [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) deliberately vulnerable web application:

- **SQL Injection (SQLi)**
- **A09: Security Logging & Monitoring Failures**
- **A10: Server-Side Request Forgery (SSRF)**

It provides an **interactive UI** that security students, researchers, and trainers can use to safely explore how these vulnerabilities behave in practice.

⚠️ **Disclaimer:** This project is for educational and authorized penetration testing **only**. Do not use against systems you don’t own or lack permission to test.

---

## 🚀 Features

### 1. SQL Injection Tester
- Loads and executes a list of SQLi payloads (`payloads.txt`) against the Juice Shop login endpoint.
- Detects successful logins or token leaks from injection.
- Displays:
  - Status codes
  - Timing information
  - Response excerpts
  - Whether a JWT token was returned
- Includes a **“Ping Login API”** button to check target connectivity.
- Logs can be viewed in a dedicated tab with request/response bodies and headers.

### 2. A09: Security Logging & Monitoring Failures
- Generates a unique **marker** and performs:
  - Bursts of failed login attempts
  - Unauthorized admin request
  - Suspicious SQLi-style search
  - Probes for exposed log file endpoints
- Summarizes verdicts:
  - `INSUFFICIENT_EVENT_LOGGING` → no marker found in logs  
  - `PUBLIC_LOG_EXPOSED` → logs accessible via public URL  
  - `SUSPICIOUS_LOGIN_RESPONSE_CODES` → suspiciously permissive responses
- Highlights how **insufficient monitoring** leaves attacks undetected.

### 3. A10: Server-Side Request Forgery (SSRF)
- Exploits the Juice Shop **“image by URL”** feature (`/profile/image-url`).
- Allows you to replace `{URL}` with attacker-controlled targets:
  - Internal services (e.g., `http://127.0.0.1:3000/ftp/log.txt`)
  - Cloud metadata endpoints (e.g., `http://169.254.169.254/latest/meta-data/`)
- Flags **“Possible SSRF: large/echoed response”** when the backend fetches and returns target content.
- Demonstrates how SSRF can be used to pivot into internal networks.

---

## 📂 Project Structure

```
.
├─ app.py                 # Main Streamlit app (SQLi, A09, SSRF tabs)
├─ payloads.txt           # Sample SQLi payloads
├─ requirements.txt       # Python dependencies
├─ README.md              # Project documentation
├─ LICENSE                # MIT license
└─ .gitignore             # Ignore venv, cache, editor files
```

---

## ⚙️ Installation & Setup

1. **Clone the repo**  
   ```bash
   git clone https://github.com/<zawadsazidvu>/juice-shop-lab.git
   cd juice-shop-lab
   ```

2. **Set up virtual environment**  
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies**  
   ```bash
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   ```

4. **Run the app**  
   ```bash
   python -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501
   ```

5. **Open in browser**  
   Visit: [http://127.0.0.1:8501](http://127.0.0.1:8501)

---

## 🛠 Usage Walkthrough

### SQL Injection
1. Go to the **SQLi Tester** tab.
2. Load `payloads.txt` or paste custom payloads.
3. Click **▶️ Run SQLi Test**.
4. View table results and detailed request/response logs.

### A09 Logging & Monitoring
1. Go to the **A09 Logging/Monitoring** tab.
2. Click **▶️ Run A09 Probe**.
3. Review verdicts (e.g., insufficient logging, exposed logs).
4. Download JSON report for analysis.

### SSRF
1. Go to the **SSRF** tab.
2. Set endpoint path: `/profile/image-url`
3. Request template: `{"imageUrl":"{URL}"}`.
4. Add target URLs like:
   ```
   http://127.0.0.1:3000/ftp/log.txt
   http://169.254.169.254/latest/meta-data/
   ```
5. Run probe and inspect responses.

---

## 📊 Example Output

### SQLi
```json
[
  {
    "payload": "' OR 1=1--",
    "status_code": 200,
    "token_found": true,
    "elapsed_ms": 142,
    "response_excerpt": "{...jwt token...}"
  }
]
```

### A09
```json
{
  "marker": "A09-20250909T124500-xyz123",
  "verdicts": ["INSUFFICIENT_EVENT_LOGGING", "PUBLIC_LOG_EXPOSED"],
  "steps": {
    "failed_logins": [...],
    "sqli_like_search": {...},
    "log_probes": [...]
  }
}
```

### SSRF
| Target URL                     | Status | Length | Note                                 |
|--------------------------------|--------|--------|--------------------------------------|
| http://127.0.0.1:3000/ftp/log.txt | 200    | 1420   | Possible SSRF: large/echoed response |
| http://169.254.169.254/latest/meta-data/ | ERR    | 0      | Connection refused                   |

---

## 🔐 Security & Ethics
- **Lab use only**: Tested on OWASP Juice Shop running locally.
- Not for attacking production systems.
- Educational purpose: to learn how to detect, exploit, and mitigate vulnerabilities.

---

## 📜 License
MIT License — see [LICENSE](LICENSE).

---

## 🙌 Acknowledgements
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) — the vulnerable web app.
- [Streamlit](https://streamlit.io) — for making quick dashboards.
- [OWASP Top 10](https://owasp.org/Top10/) — security standard this project is aligned with.
