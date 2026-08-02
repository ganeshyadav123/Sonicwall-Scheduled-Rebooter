# 🔒 SonicWall Firewall Reboot Scheduler (Open Source)

An enterprise-grade, self-hosted web application designed to schedule, orchestrate, verify, and monitor reboots across multiple SonicWall firewalls concurrently with zero plaintext password storage on disk.

This application uses a fully decoupled architecture: a zero-dependency, ultra-fast vanilla JS/CSS frontend coupled with a hardened, production-ready Python Flask backend running under Waitress WSGI.

---

## 📖 Table of Contents
1. [What Is This App & What Is Its Purpose?](#-what-is-this-app--what-is-its-purpose)
2. [Step-by-Step User Guide (What to Click & How to Work)](#-step-by-step-user-guide-what-to-click--how-to-work)
3. [Complete UI Buttons & Options Reference](#-complete-ui-buttons--options-reference)
4. [Security & Cryptography Hardening](#-security--cryptography-hardening)
5. [Architecture & Real-Time SSE Engine](#-architecture--real-time-sse-engine)
6. [Project Directory Layout](#-project-directory-layout)
7. [Installation & Getting Started](#-installation--getting-started)
8. [Developer Guide (How to Modify & Extend)](#-developer-guide-how-to-modify--extend)
9. [License](#-license)

---

## 🎯 What Is This App & What Is Its Purpose?

In enterprise networks managing dozens or hundreds of SonicWall firewalls, performing routine firmware maintenance or system reboots presents several critical operational challenges:
1. **Network Spike Risks**: Rebooting multiple core or branch firewalls at the exact same second can trigger severe network routing flaps and power surges.
2. **Credential Exposure**: Storing firewall admin credentials in plain CSV files or databases introduces major security risks.
3. **Monitoring Alarm Storms**: Automated network monitoring systems (PRTG, SolarWinds, Datadog) trigger massive downtime alert storms when firewalls reboot during scheduled maintenance.
4. **Verification Overhead**: Admins must manually check each device post-reboot to ensure it came back online successfully.

### How This App Solves It:
- **AES-256-GCM Secure Encrypted Files**: Passwords are saved in encrypted `.enc` files using 600,000 PBKDF2-SHA256 iterations. Credentials exist strictly in RAM while the app is active and are never written to disk in plaintext.
- **Intelligent Cascading Spacing**: Automatically spaces out reboots across queued firewalls (e.g., 5-minute intervals) so network links reboot sequentially.
- **Automated Pre-Reboot & Post-Reboot SMTP Alerts**: 1 minute before each reboot, the app dispatches an email to your monitoring team ("Ignore Alerts for FW-HQ-01"). Once the reboot is verified post-boot via SSH polling, it dispatches a resume confirmation email ("Resume Monitoring").
- **Live Terminal SSE Streaming**: Real-time HTTP log streaming to monitor terminal outputs, progress metrics, and uptime responses.

---

## 🕹️ Step-by-Step User Guide (What to Click & How to Work)

The user interface is organized into a intuitive 4-Step Wizard:

```
[ Step 1: Upload / Decrypt ] ➜ [ Step 2: Select & Inspect ] ➜ [ Step 3: Schedule & Space ] ➜ [ Step 4: Live Execution ]
```

### 📥 Step 1: Upload or Decrypt Inventory
1. **To Upload a Plain CSV**:
   - Click the big **"Browse CSV File"** button (or drag & drop your `.csv` file onto the drop zone).
   - Your CSV must have these exact header columns: `Name, IP, Port, Username, Password, Site`.
   - *Example*:
     ```csv
     Name,IP,Port,Username,Password,Site
     FW-HQ-01,192.168.1.1,22,admin,MyPass123!,Headquarters
     FW-Branch-01,10.0.1.1,22,admin,MyPass456!,New York
     ```
2. **To Encrypt & Save Your CSV (AES-256)**:
   - Click the **"🔒 Save AES-256 .enc"** link in the toolbar (or click the green encrypt button after loading).
   - Enter a **Master Passphrase** (must be 12+ characters with uppercase, lowercase, digit, and special char).
   - Confirm your passphrase. An encrypted `inventory_encrypted.enc` file will download automatically.
3. **To Load an Encrypted `.enc` File**:
   - Click **"Browse CSV File"** and select your `.enc` file.
   - Enter your Master Passphrase when prompted. The credentials decrypt into RAM and automatically load Step 2.

---

### 🔍 Step 2: Select Devices & Inspect Uptime
1. **Filter & Select**:
   - Use the **Site Filter Pills** (`All Sites`, `Headquarters`, `New York`, etc.) or the **Search Bar** to find specific firewalls.
   - Check the individual checkboxes next to the firewalls you want to target (or click the **"Select All"** dropdown button).
2. **Inspect Active Status (Optional)**:
   - Click **"🔍 Check Uptime"** to query active SSH uptimes across all selected firewalls.
   - Click **"🌐 Check Timezone"** to verify clock alignment across target hardware.
   - Click **"📥 Export Uptime CSV"** to save a snapshot report of device responses.
3. **Proceed**:
   - Click the blue **"Next: Schedule ➔"** button.

---

### ⏰ Step 3: Set Schedule & Spacing
1. **Choose Execution Mode**:
   - **Reboot Now**: Triggers immediate reboot execution upon starting.
   - **Schedule at Specific Date/Time**: Allows setting exact future dates and times.
2. **Apply Automatic Cascading Spacing (Crucial for Multi-Firewall Reboots)**:
   - In the **Quick Spacing Interval** dropdown, choose a gap: `No Gap (Concurrent)`, `2 minutes`, `5 minutes`, `10 minutes`, or `15 minutes`.
   - Click **"⚡ Apply Spacing to Selected"**. The application will automatically space each firewall's reboot time sequentially (e.g., FW1 @ 03:00 AM, FW2 @ 03:05 AM, FW3 @ 03:10 AM).
3. **Proceed**:
   - Click the green **"Next: Review & Execute ➔"** button.

---

### 🚀 Step 4: Execute & Monitor
1. **Start Execution**:
   - Review your target summary list.
   - Click the big green **"🚀 Start Scheduled Reboots"** button.
2. **Monitor Real-Time Progress**:
   - Watch the **Live Progress Bar** and counters (**Total**, **Completed**, **Successful**, **Failed**).
   - View the live **SSH Logs Terminal** stream at the bottom of the page.
3. **Emergency Abort**:
   - If needed, click the red **"⏹️ Stop Execution"** button to abort remaining queued reboots.

---

## 🎛️ Complete UI Buttons & Options Reference

### Header Bar:
- **`⚙️ Settings` Button**: Opens SMTP email configuration modal.
  - *Fields*: SMTP Host, Port (587/465), Username, App Password, Recipient Email list, Enable Emails toggle, Enable Monitoring timeout.
  - *Buttons*: **Test Email** (sends test alert), **Save Settings**, **Cancel**.

### Step 1 Panel (Upload & Encrypt):
- **`Browse Files` Button**: Opens native file picker for `.csv` or `.enc` files.
- **`🔒 Encrypt a CSV File` Button**: Encrypts loaded CSV into AES-256 `.enc`.
- **`📥 Download Sample CSV`**: Downloads clean CSV template (`sample_firewalls.csv`).

### Step 2 Panel (Selection & Actions):
- **`Search Input`**: Instant text filter by name, IP, or site.
- **`Site Filter Pills`**: Filter table by site location.
- **`Select All Dropdown`**: Quick select/deselect all rows.
- **`🔍 Check Uptime`**: SSH queries active uptime for selected firewalls.
- **`🌐 Check Timezone`**: Queries hardware system clock settings.
- **`📥 Export Uptime CSV`**: Downloads active status table.
- **`🔒 Save AES-256 .enc`**: Encrypts selected inventory.

### Step 3 Panel (Schedule & Spacing):
- **`Reboot Now / Schedule Pills`**: Switches between immediate and future scheduling.
- **`Quick Date & Time Inputs`**: Sets target base start time.
- **`Quick Interval Dropdown`**: Sets spacing gap (0 to 15 min).
- **`⚡ Apply Spacing to Selected`**: Cascades times sequentially across rows.

### Step 4 Panel (Execution):
- **`🚀 Start Scheduled Reboots`**: Commences thread executor and SSE streaming.
- **`⏹️ Stop Execution`**: Aborts active queue.
- **`🧹 Clear Logs`**: Resets UI log console.

---

## 🔐 Security & Cryptography Hardening

### OWASP 2023 AES-256-GCM Specification
- **Algorithm**: `AES-256-GCM` (Galois/Counter Mode authenticated encryption).
- **Key Derivation Function**: `PBKDF2HMAC` with `SHA-256`.
- **Stretching Rounds**: **600,000 iterations** (OWASP 2023 guideline).
- **Salt & IV**: 32-byte (256-bit) random salt (`os.urandom(32)`), 12-byte IV.
- **Integrity**: `v2` payload with Additional Authenticated Data (AAD) header binding.
- **Passphrase Rules**: Minimum 12 characters (uppercase, lowercase, number, special char).

### Memory Safety & Process Cleanup
- **`_secure_zero()`**: Overwrites mutable `bytearray` buffers in RAM with null bytes (`\x00`) immediately after key derivation.
- **`finally:` Blocks**: Explicit `del key, passphrase, csv_text, decrypted_bytes` calls in all endpoints.
- **Garbage Collection**: Forces `gc.collect()` immediately after sensitive operations.

---

## 🏗️ Architecture & Real-Time SSE Engine

```
[ Client Browser: Vanilla JS / CSS ]
          │
          ▼ (REST API & SSE /api/status)
[ Backend: Flask + Waitress WSGI ]
   ├── [ Config Engine (config.json) ]
   ├── [ PyCA Cryptography Engine ]
   └── [ Paramiko SSH Worker Threads + Lock Files ]
```

- **Thread-Safe Locks**: `threading.Lock()` per firewall IP prevents concurrent connection collisions.
- **Server-Sent Events (SSE)**: `/api/status` streams live JSON status packets to client `EventSource` without polling overhead.

---

## 📂 Project Directory Layout

```
├── backend/
│   ├── app.py                  # Flask routes, SSH workers, crypto engine
│   ├── config.json             # Local SMTP config (Git-ignored)
│   ├── config.json.example     # Clean template for open-source setup
│   ├── requirements.txt        # Locked python dependencies
│   └── venv/                   # Python virtual environment
├── frontend/
│   ├── app.js                  # Application state machine & UI bindings
│   ├── index.html              # Modern 4-step wizard interface
│   ├── index.css               # Vanilla CSS glassmorphism styling
│   └── papaparse.min.js        # CSV parser engine
├── .gitignore                  # Excludes config.json, venv, and .enc files
├── README.md                   # This instruction manual
├── run_production.bat          # Waitress WSGI production launcher
├── start.bat                   # Development launcher
└── sample_firewalls.csv        # Template CSV inventory
```

---

## 🚀 Installation & Getting Started

### Prerequisites
- Python 3.11+
- Git

### Quick Setup (Windows)
1. **Clone Repository**:
   ```bash
   git clone https://github.com/ganeshyadav123/Sonicwall-Scheduled-Rebooter
   cd Sonicwall-scheduled-Rebooter
   ```
2. **Run Production Server**:
   - Double-click **`run_production.bat`**.
   - The script will automatically create `backend/venv`, install dependencies, launch Waitress WSGI on `http://0.0.0.0:5000`, and open your browser at **`http://localhost:5000`**.

### Manual Setup (Linux / macOS)
```bash
python3 -m venv backend/venv
source backend/venv/bin/activate
pip install -r backend/requirements.txt
python backend/app.py
```
Open **`http://localhost:5000`** in your web browser.

---

## 🛠️ Developer Guide (How to Modify & Extend)

### Adding New SSH CLI Commands
To add a pre-reboot backup command or custom diagnostic check, locate the Paramiko channel block in `backend/app.py`:
```python
# Send custom command to SonicWall CLI:
chan.send("show status\n")
```

### Customizing UI Themes
CSS design tokens are defined at the top of `frontend/index.css`:
```css
:root {
  --background-dark: #0a0e1a;
  --accent-cyan: #00d4ff;
  --accent-green: #10b981;
}
```

Note: 
1.SSH should be enabled on the interface of the firewall which you using to schedule the reboot and for the security purposes allow ssh for only trusted IP's in SonicWall .
2.This app would need an account in the firewall which has atleast limited Admin role.
3.Don't close the backend cli which is running after scheduling the firewalls for pre & post alerts(unless you don't need any alerts).
4.This tool uses Paramiko library to SSH into the firewalls and it was tested with the Tz & Nsv's and Nsa models(works with any sonicWall).
5.The run_production.bat file gets executed in windows only for linux & mac run the backend file manually and open the frontend file.
6.Start.bat is also works but it run as dev version where frontend file open automatically.
7.The update.bat file used to update the dependencies in the app if new version is released.
8.The word document file is also included for the get the overall view and approvals to use the app.
9.For the SMTP only basic auth account is supoorted, enable the App passpwrd and get the credentials and upload in the app which saves the configuration in the bacekend>config.json file.
so if you are sharing with your friends directly share my github repo url and clone it by without getting your smtp passwords gettting shared.
10.The whole pacakges are veing audited with Pip audit and all the version are up to date, if your organisation woried about the zero day attacks put the app in the DMZ zone and close the wan>lan & dmz>lan rules.
---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for more information.
