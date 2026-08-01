"""
SonicWall Firewall Reboot Scheduler - Flask Backend
====================================================
SSH into SonicWall firewalls to:
  - Schedule reboots (per-firewall datetime)
  - Check uptime
  - Test connectivity

Each firewall can have its own reboot schedule time.
"""

import collections
import csv
import io
import json
import logging
import os
import queue
import smtplib
import threading
import time
import gc
import uuid
from datetime import datetime, timedelta
from email.header import Header
from email.mime.text import MIMEText

import paramiko
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, Response, jsonify, request
from flask_cors import CORS

# ---------------------------------------------------------------------------
# App & Logging
# ---------------------------------------------------------------------------

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
# Allow all origins for API routes so local dev servers, file://, and Live Server work seamlessly
CORS(app, resources={r"/api/*": {"origins": "*"}})

@app.before_request
def log_request_info():
    logger.info(f"Incoming Request: {request.method} {request.path}")

@app.after_request
def add_no_cache_headers(response):
    logger.info(f"Response: {request.method} {request.path} -> {response.status}")
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route("/")
def index():
    return app.send_static_file("index.html")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Thread-Safe Shared State — Reboot
# ---------------------------------------------------------------------------

status_queue: queue.Queue = queue.Queue()
state_lock = threading.Lock()
is_running: bool = False
cancel_flag: bool = False
current_status: dict = {}

# ---------------------------------------------------------------------------
# Thread-Safe Shared State — Uptime
# ---------------------------------------------------------------------------

uptime_queue: queue.Queue = queue.Queue()
uptime_lock = threading.Lock()
is_uptime_running: bool = False
uptime_cancel_flag: bool = False

# ---------------------------------------------------------------------------
# Thread-Safe Shared State — Timezone
# ---------------------------------------------------------------------------

timezone_queue: queue.Queue = queue.Queue()
timezone_lock = threading.Lock()
is_timezone_running: bool = False
timezone_cancel_flag: bool = False

# Per-IP lock to serialize concurrent SSH sessions to the same firewall
firewall_locks = collections.defaultdict(threading.Lock)

# ---------------------------------------------------------------------------
# Thread-Safe Shared State — Schedule Check & Cancel
# ---------------------------------------------------------------------------

schedule_queue: queue.Queue = queue.Queue()
schedule_lock = threading.Lock()
is_schedule_running: bool = False
schedule_cancel_flag: bool = False

# ---------------------------------------------------------------------------
# Configuration & SMTP Email Helpers
# ---------------------------------------------------------------------------

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

def _load_settings() -> dict:
    default_settings = {
        "smtp_server": "",
        "smtp_port": 587,
        "smtp_username": "",
        "smtp_password": "",
        "recipient_email": "",
        "enable_emails": False,
        "enable_monitoring": True,
        "monitoring_timeout_minutes": 10
    }
    if not os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(default_settings, f, indent=2)
            return default_settings
        except Exception as e:
            logger.warning("Failed to create default config: %s", e)
            return default_settings

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Ensure all keys exist
            for k, v in default_settings.items():
                if k not in data:
                    data[k] = v
            return data
    except Exception as e:
        logger.warning("Failed to read config.json: %s. Using defaults.", e)
        return default_settings


def _save_settings(settings: dict) -> bool:
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
        return True
    except Exception as e:
        logger.error("Failed to save config: %s", e)
        return False


def _send_notification_email(subject: str, body: str) -> bool:
    settings = _load_settings()
    if not settings.get("enable_emails"):
        logger.info("Email notifications are disabled in settings.")
        return False

    smtp_server = settings.get("smtp_server")
    smtp_port = settings.get("smtp_port", 587)
    try:
        smtp_port = int(smtp_port)
    except ValueError:
        smtp_port = 587
    username = settings.get("smtp_username")
    password = settings.get("smtp_password")
    recipient = settings.get("recipient_email")

    if not (smtp_server and username and recipient):
        logger.warning("SMTP configuration is incomplete. Cannot send email.")
        return False

    # Support multiple recipients split by comma or semicolon
    recipients_list = []
    for r in recipient.replace(";", ",").split(","):
        clean_r = r.strip()
        if clean_r:
            recipients_list.append(clean_r)

    if not recipients_list:
        logger.warning("SMTP configuration contains no valid recipient emails.")
        return False

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = Header(subject, "utf-8")
    msg["From"] = username
    msg["To"] = ", ".join(recipients_list)

    try:
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=10)
        else:
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
            server.ehlo()
            if server.has_extn("STARTTLS") or smtp_port == 587:
                server.starttls()
                server.ehlo()

        if username and password:
            server.login(username, password)
        server.sendmail(username, recipients_list, msg.as_string())
        server.quit()
        logger.info("SMTP email sent successfully to %d recipients: %s", len(recipients_list), subject)
        return True
    except Exception as exc:
        logger.error("Failed to send email via SMTP: %s", exc)
        return False


def _poll_and_verify_reboot(firewall: dict, timeout_seconds: int = 600) -> tuple:
    """Poll a firewall via SSH Uptime until it comes back online with low uptime, or timeout."""
    fw_id = firewall["id"]
    ip = firewall["ip"]
    
    initial_delay_secs = 200
    logger.info("Monitoring %s: Sleeping %ds for shutdown & reboot initialization...", ip, initial_delay_secs)
    
    # Poll cancellation flag in state
    step = 5
    for _ in range(0, initial_delay_secs, step):
        if cancel_flag:
            return False, "Cancelled by user"
        time.sleep(step)

    start_time = time.time()
    attempt = 0
    while time.time() - start_time < timeout_seconds:
        if cancel_flag:
            return False, "Cancelled by user"
            
        attempt += 1
        _push_reboot_status(fw_id, "verifying", f"Checking online status (Attempt {attempt})...")
        
        ssh = None
        shell = None
        try:
            # Short connection timeout for polling
            ssh = _ssh_connect(firewall, timeout=8)
            shell = ssh.invoke_shell()
            shell.settimeout(8.0)
            
            _sonicwall_cli_login(shell, firewall)
            _send_command(shell, "no cli pager", wait=1.0)
            
            output = _send_command(shell, "show status", wait=1.5)
            
            # Find uptime
            uptime_val = ""
            for line in output.splitlines():
                if "uptime" in line.lower() or "up time" in line.lower():
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        uptime_val = parts[1].strip()
                    break
                    
            if not uptime_val:
                logger.warning("Could not find uptime line in show status for verification of %s", ip)
                time.sleep(15)
                continue
                
            is_new_uptime = True
            low_val = uptime_val.lower()
            if "day" in low_val and not low_val.startswith("0 day"):
                is_new_uptime = False
            elif "hour" in low_val and not low_val.startswith("0 hour") and not "00:" in low_val:
                is_new_uptime = False
                
            if is_new_uptime:
                logger.info("Verification success for %s! Uptime: %s", ip, uptime_val)
                return True, uptime_val
            else:
                logger.warning("Firewall %s is reachable but uptime is high: %s. Still waiting for reboot.", ip, uptime_val)
                
        except Exception as e:
            logger.info("Firewall %s is offline/rebooting... (%s)", ip, str(e)[:80])
            
        finally:
            if ssh:
                if shell:
                    try:
                        shell.send("exit\n")
                        time.sleep(0.2)
                    except Exception:
                        pass
                ssh.close()
                
        for _ in range(0, 20, 5):
            if cancel_flag:
                return False, "Cancelled by user"
            time.sleep(5)
            
    return False, "Verification timeout exceeded"

# ---------------------------------------------------------------------------
# SSH Helpers
# ---------------------------------------------------------------------------

def _ssh_connect(firewall: dict, timeout: int = 30) -> paramiko.SSHClient:
    """Create and return an SSH connection to a firewall."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=firewall["ip"],
        port=int(firewall.get("port", 22)),
        username=firewall["username"],
        password=firewall["password"],
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return ssh


def _read_until_ready(shell, timeout: float = 5.0) -> str:
    """Read from the shell until no more data arrives for a short pause."""
    output = ""
    end_time = time.time() + timeout
    while time.time() < end_time:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode("utf-8", errors="replace")
            output += chunk
            time.sleep(0.3)  # small pause to let more data arrive
        else:
            time.sleep(0.5)
            # Check once more after a pause
            if not shell.recv_ready():
                break
    return output


def _sonicwall_cli_login(shell, firewall: dict) -> str:
    """Handle SonicWall's post-SSH CLI login prompts.

    After SSH authentication, SonicWall may prompt for:
      User: <username>
      Password: <password>
    before reaching the CLI prompt (>).
    This function detects and responds to those prompts.
    """
    # Read initial banner/prompt (up to 5 seconds)
    output = _read_until_ready(shell, timeout=5.0)
    logger.info("CLI initial output: %s", output.strip()[:200])

    # Check for User: prompt
    if "user:" in output.lower():
        logger.info("SonicWall CLI asking for username — sending")
        shell.send(firewall["username"] + "\n")
        time.sleep(1)
        output += _read_until_ready(shell, timeout=3.0)

    # Check for Password: prompt
    if "password:" in output.lower():
        logger.info("SonicWall CLI asking for password — sending")
        shell.send(firewall["password"] + "\n")
        time.sleep(2)
        output += _read_until_ready(shell, timeout=5.0)

    # Check if login succeeded — look for the prompt (>) or any non-error output
    if "access denied" in output.lower() or "login failed" in output.lower():
        logger.warning("SonicWall CLI login appears to have failed")

    return output


def _send_command(shell, command: str, wait: float = 3.0) -> str:
    """Send a command to an interactive shell and read the response."""
    time.sleep(0.3)  # Delay to allow network/SSH buffer to settle between commands
    
    # Clear any residual output in the channel read buffer before sending a new command
    if shell.recv_ready():
        try:
            shell.recv(65535)
        except Exception:
            pass
            
    shell.send(command + "\n")
    time.sleep(wait)
    output = _read_until_ready(shell, timeout=wait + 2.0)
    return output


def _handle_confirmation(shell, output: str) -> str:
    """If the output contains a confirmation prompt, send 'yes' and read more."""
    confirm_keywords = ["yes", "y/n", "confirm", "(y/n)"]
    if any(kw in output.lower() for kw in confirm_keywords):
        logger.info("Confirmation prompt detected — sending 'yes'")
        shell.send("yes\n")
        time.sleep(2)
        output += _read_until_ready(shell, timeout=3.0)
    return output

# ---------------------------------------------------------------------------
# Status Push Helpers
# ---------------------------------------------------------------------------

def _push_reboot_status(fw_id: str, status: str, message: str = "") -> None:
    event = {"id": fw_id, "status": status, "message": message}
    status_queue.put(event)
    with state_lock:
        current_status[fw_id] = event
    logger.info("Reboot %s -> %s : %s", fw_id, status, message[:120])


def _push_uptime_status(fw_id: str, status: str, message: str = "", uptime: str = "", fw_time: str = "") -> None:
    event = {
        "id": fw_id,
        "status": status,
        "message": message,
        "uptime": uptime,
        "fw_time": fw_time
    }
    uptime_queue.put(event)
    logger.info("Uptime %s -> %s : %s", fw_id, status, message[:120])


def _push_timezone_status(fw_id: str, status: str, message: str = "", fw_time: str = "") -> None:
    event = {
        "id": fw_id,
        "status": status,
        "message": message,
        "fw_time": fw_time
    }
    timezone_queue.put(event)
    logger.info("Timezone %s -> %s : %s", fw_id, status, message[:120])


def _push_schedule_status(fw_id: str, status: str, message: str = "", has_schedule: bool = False) -> None:
    event = {"id": fw_id, "status": status, "message": message, "hasSchedule": has_schedule}
    schedule_queue.put(event)
    logger.info("Schedule %s -> %s : %s (hasSchedule=%s)", fw_id, status, message[:120], has_schedule)

# ---------------------------------------------------------------------------
# Reboot Execution — Per-Firewall Datetime
# ---------------------------------------------------------------------------

def get_chicago_offset_hours(dt: datetime) -> int:
    """Return US Central Time (CST/CDT) offset in hours for a given datetime.
       US DST begins on the second Sunday of March and ends on the first Sunday of November.
    """
    try:
        # 2nd Sunday in March
        march_1st = datetime(dt.year, 3, 1)
        w_march = march_1st.weekday()
        dst_start = datetime(dt.year, 3, 1 + (6 - w_march) % 7 + 7, 2)
        
        # 1st Sunday in November
        nov_1st = datetime(dt.year, 11, 1)
        w_nov = nov_1st.weekday()
        dst_end = datetime(dt.year, 11, 1 + (6 - w_nov) % 7, 2)
        
        if dst_start <= dt < dst_end:
            return -5  # CDT (UTC-5)
        else:
            return -6  # CST (UTC-6)
    except Exception:
        # Fallback to standard Central Standard Time (CST)
        return -6



def _monitor_scheduled_reboot(firewall: dict, reboot_time: datetime) -> None:
    """Thread function that runs in the background, sleeping until the scheduled reboot time, 
       then triggers the pre-reboot email, waits for reboot, checks status, and sends post-reboot email.
       reboot_time is a timezone-aware UTC datetime.
    """
    fw_id = firewall["id"]
    name = firewall.get("name", "Firewall")
    ip = firewall["ip"]
    site = firewall.get("site", "N/A")
    
    from datetime import timezone
    
    # Calculate pre-reboot email time (1 minute before reboot)
    now_utc = datetime.now(timezone.utc)
    pre_reboot_time = reboot_time - timedelta(minutes=1)
    
    # Sleep until 1 minute before reboot time
    sleep_secs_pre = (pre_reboot_time - now_utc).total_seconds()
    if sleep_secs_pre > 0:
        logger.info("Scheduler monitor for %s (%s) sleeping for %.1f seconds until pre-reboot alert at %s", name, ip, sleep_secs_pre, pre_reboot_time)
        time.sleep(sleep_secs_pre)
        
    logger.info("Sending pre-reboot notification email for %s (%s)", name, ip)
    settings = _load_settings()
    
    dt_string = firewall.get("datetime", "")
    display_time = ""
    if dt_string:
        try:
            parts = dt_string.split(":")
            if len(parts) >= 5:
                display_time = f"{parts[0]}-{parts[1]}-{parts[2]} {parts[3]}:{parts[4]}"
        except Exception:
            pass
    if not display_time:
        display_time = reboot_time.strftime('%Y-%m-%d %I:%M:%S %p UTC')
    
    # 1. Send Pre-reboot email (1 minute before the reboot triggers)
    subject_pre = f"Ignore Alerts Rebooting firewall: {name} - Maintainance Activity"
    body_pre = (
        f"Maintenance starting.\n\n"
        f"Firewall Name: {name}\n"
        f"Firewall IP: {ip}\n"
        f"Site: {site}\n"
        f"Reboot Scheduled Time: {display_time}\n\n"
        f"Ignore alerts"
    )
    _send_notification_email(subject_pre, body_pre)
    
    # Sleep the remaining time until the actual reboot_time window
    sleep_secs_reboot = (reboot_time - datetime.now(timezone.utc)).total_seconds()
    if sleep_secs_reboot > 0:
        logger.info("Scheduler monitor for %s (%s) sleeping for %.1f seconds until actual reboot time %s", name, ip, sleep_secs_reboot, reboot_time)
        time.sleep(sleep_secs_reboot)
        
    logger.info("Scheduled reboot window reached for %s (%s). Executing reboot verification.", name, ip)
    
    # 2. Wait and poll status if monitoring is enabled
    if settings.get("enable_monitoring", True):
        timeout_seconds = int(settings.get("monitoring_timeout_minutes", 10)) * 60
        success, info = _poll_and_verify_reboot(firewall, timeout_seconds)
        
        # 3. Send Post-reboot email
        if success:
            subject_post = f"Resume Monitoring - {name}"
            body_post = (
                f"Maintenance complete.\n\n"
                f"Firewall Name: {name}\n"
                f"Firewall IP: {ip}\n"
                f"Site: {site}\n"
                f"Status: Online (Verified)\n"
                f"Current Uptime: {info}\n\n"
                f"Resume alerts"
            )
            _send_notification_email(subject_post, body_post)
        else:
            subject_post = f"Reboot Verification failed - {name}"
            body_post = (
                f"Maintenance verification failed/timed out.\n\n"
                f"Firewall Name: {name}\n"
                f"Firewall IP: {ip}\n"
                f"Site: {site}\n"
                f"Status: Verification failed or timed out: {info}\n\n"
                f"Resume alerts"
            )
            _send_notification_email(subject_post, body_post)


def execute_reboot(firewall: dict) -> None:
    """SSH into one firewall and schedule/execute a reboot.

    Each firewall dict has its own 'mode' and 'datetime' fields:
      mode='now'  -> sends 'restart now'
      mode='at'   -> sends 'restart at YYYY:MM:DD:HH:MM:SS'
    """
    fw_id = firewall["id"]
    mode = firewall.get("mode", "now")
    dt_string = firewall.get("datetime", "")
    name = firewall.get("name", "Firewall")
    ip = firewall["ip"]
    site = firewall.get("site", "N/A")

    from datetime import timezone, timedelta
    parsed_dt_utc = None
    
    # Build command
    if mode == "at" and dt_string:
        try:
            local_dt = datetime.strptime(dt_string, "%Y:%m:%d:%H:%M:%S")
            offset_hours = get_chicago_offset_hours(local_dt)
            tz_chicago = timezone(timedelta(hours=offset_hours))
            dt_chicago = local_dt.replace(tzinfo=tz_chicago)
            parsed_dt_utc = dt_chicago.astimezone(timezone.utc)
            
            now_utc = datetime.now(timezone.utc)
            diff_seconds = (parsed_dt_utc - now_utc).total_seconds()
            diff_minutes = int(round(diff_seconds / 60.0))
            if diff_minutes > 0:
                command = f"restart in {diff_minutes} minutes"
                logger.info("Scheduling CST/CDT timezone-safe reboot: using '%s'", command)
            else:
                command = "restart now"
                mode = "now"
                parsed_dt_utc = now_utc
        except Exception as e:
            logger.warning("Failed to parse schedule datetime %s as CST: %s. Using restart now.", dt_string, e)
            command = "restart now"
            mode = "now"
            parsed_dt_utc = datetime.now(timezone.utc)
    else:
        command = "restart now"
        parsed_dt_utc = datetime.now(timezone.utc)

    # If immediate reboot ('now') and email is enabled, send pre-reboot notification right before SSH
    if mode == "now":
        subject_pre = f"Ignore Alerts Rebooting firewall: {name} - Maintainance Activity"
        body_pre = (
            f"Maintenance starting.\n\n"
            f"Firewall Name: {name}\n"
            f"Firewall IP: {ip}\n"
            f"Site: {site}\n"
            f"Reboot Triggered Time: {datetime.now().strftime('%Y-%m-%d %I:%M:%S %p')}\n\n"
            f"Ignore alerts"
        )
        _send_notification_email(subject_pre, body_pre)

    _push_reboot_status(fw_id, "connecting", f"Waiting for lock on {ip}...")

    ssh = None
    shell = None
    command_succeeded = False
    truncated_msg = "Reboot scheduled successfully"
    
    try:
        with firewall_locks[ip]:
            _push_reboot_status(fw_id, "connecting", f"Connecting to {ip}...")
            ssh = _ssh_connect(firewall, timeout=30)
            _push_reboot_status(fw_id, "connected", f"Connected to {firewall['name']}")

            shell = ssh.invoke_shell()
            shell.settimeout(15.0)
            # Post-SSH CLI Login check
            _sonicwall_cli_login(shell, firewall)

            # Disable CLI pager pagination
            _send_command(shell, "no cli pager", wait=1.0)

            _push_reboot_status(fw_id, "executing", f"Sending: {command}")
            output = _send_command(shell, command, wait=3.0)
            output = _handle_confirmation(shell, output)

            # Parse command output to extract meaningful error or success message
            clean_output = output.strip()
            lines = []
            for line in clean_output.splitlines():
                line_lower = line.strip().lower()
                # Filter out echoed commands, confirmation prompts, responses, and system headers
                if "processing command" in line_lower:
                    continue
                if command in line_lower:
                    continue
                if "admin@" in line_lower:
                    continue
                if "are you sure" in line_lower or "wish to restart" in line_lower or "yes/cancel" in line_lower:
                    continue
                if "[cancel]:" in line_lower or line_lower == "yes":
                    continue
                if not line.strip():
                    continue
                lines.append(line.strip())

            meaningful_message = " | ".join(lines) if lines else "Reboot scheduled successfully"
            truncated_msg = meaningful_message[:300]

            # Check if the output indicates an error
            is_error = False
            error_keywords = ["error", "invalid", "failed", "cannot", "denied", "timed out", "access denied"]
            for line in lines:
                line_lower = line.lower()
                if any(k in line_lower for k in error_keywords):
                    is_error = True
                    break

            if is_error:
                _push_reboot_status(fw_id, "failed", truncated_msg)
            else:
                command_succeeded = True
                _push_reboot_status(fw_id, "success", truncated_msg)

    except paramiko.AuthenticationException:
        _push_reboot_status(fw_id, "failed", "Authentication failed — check username/password")
    except paramiko.SSHException as exc:
        _push_reboot_status(fw_id, "failed", f"SSH error: {exc}")
    except Exception as exc:
        _push_reboot_status(fw_id, "failed", f"Error: {exc}")
    finally:
        if ssh:
            if shell:
                try:
                    shell.send("exit\n")
                    time.sleep(0.2)
                except Exception:
                    pass
            ssh.close()

    # If the reboot command succeeded, now we handle the monitoring phase
    if command_succeeded:
        settings = _load_settings()
        if mode == "now":
            # If verification is enabled, we perform inline polling so the batch worker is blocked
            if settings.get("enable_monitoring", True):
                timeout_seconds = int(settings.get("monitoring_timeout_minutes", 10)) * 60
                success, info = _poll_and_verify_reboot(firewall, timeout_seconds)
                
                if success:
                    _push_reboot_status(fw_id, "success", f"Online (Uptime: {info})")
                    subject_post = f"Resume Monitoring - {name}"
                    body_post = (
                        f"Maintenance complete.\n\n"
                        f"Firewall Name: {name}\n"
                        f"Firewall IP: {ip}\n"
                        f"Site: {site}\n"
                        f"Status: Online (Verified)\n"
                        f"Current Uptime: {info}\n\n"
                        f"Resume alerts"
                    )
                    _send_notification_email(subject_post, body_post)
                else:
                    _push_reboot_status(fw_id, "failed", f"Verification Failed: {info}")
                    subject_post = f"Reboot Verification failed - {name}"
                    body_post = (
                        f"Maintenance verification failed/timed out.\n\n"
                        f"Firewall Name: {name}\n"
                        f"Firewall IP: {ip}\n"
                        f"Site: {site}\n"
                        f"Status: Verification failed or timed out: {info}\n\n"
                        f"Resume alerts"
                    )
                    _send_notification_email(subject_post, body_post)
        else:
            # For future scheduled reboots, spawn a daemon thread to sleep and monitor it when the time comes
            if settings.get("enable_monitoring", True) or settings.get("enable_emails", False):
                t = threading.Thread(
                    target=_monitor_scheduled_reboot, 
                    args=(firewall, parsed_dt_utc), 
                    daemon=True
                )
                t.start()

# ---------------------------------------------------------------------------
# Uptime Execution
# ---------------------------------------------------------------------------

def execute_uptime(firewall: dict) -> None:
    """SSH into one firewall and retrieve its uptime via 'show status'."""
    fw_id = firewall["id"]
    ip = firewall["ip"]
    _push_uptime_status(fw_id, "connecting", f"Waiting for lock on {ip}...")

    ssh = None
    shell = None
    try:
        with firewall_locks[ip]:
            _push_uptime_status(fw_id, "connecting", f"Connecting to {ip}...")
            ssh = _ssh_connect(firewall, timeout=15)
            _push_uptime_status(fw_id, "connected", f"Connected to {firewall['name']}")

            shell = ssh.invoke_shell()
            shell.settimeout(10.0)
            # Post-SSH CLI Login check
            _sonicwall_cli_login(shell, firewall)

            # Disable CLI pager pagination
            _send_command(shell, "no cli pager", wait=1.0)

            _push_uptime_status(fw_id, "fetching", "Running: show status")
            output_status = _send_command(shell, "show status", wait=3.0)

            # Try to extract uptime line
            uptime_val = ""
            for line in output_status.splitlines():
                if "uptime" in line.lower() or "up time" in line.lower():
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        uptime_val = parts[1].strip()
                    else:
                        # If there's no colon, clean it up
                        uptime_val = line.replace("Uptime", "").replace("uptime", "").strip()
                    break

            if not uptime_val:
                uptime_val = "Not found"

            _push_uptime_status(
                fw_id,
                "success",
                message=uptime_val,
                uptime=uptime_val,
                fw_time=""
            )

    except paramiko.AuthenticationException:
        _push_uptime_status(fw_id, "failed", "Authentication failed")
    except paramiko.SSHException as exc:
        _push_uptime_status(fw_id, "failed", f"SSH error: {exc}")
    except Exception as exc:
        _push_uptime_status(fw_id, "failed", f"Error: {exc}")
    finally:
        if ssh:
            if shell:
                try:
                    shell.send("exit\n")
                    time.sleep(0.2)
                except Exception:
                    pass
            ssh.close()


def execute_timezone(firewall: dict) -> None:
    """SSH into one firewall and retrieve its timezone & time via 'show time'."""
    fw_id = firewall["id"]
    ip = firewall["ip"]
    _push_timezone_status(fw_id, "connecting", f"Waiting for lock on {ip}...")

    ssh = None
    shell = None
    try:
        with firewall_locks[ip]:
            _push_timezone_status(fw_id, "connecting", f"Connecting to {ip}...")
            ssh = _ssh_connect(firewall, timeout=15)
            _push_timezone_status(fw_id, "connected", f"Connected to {firewall['name']}")

            shell = ssh.invoke_shell()
            shell.settimeout(10.0)
            # Post-SSH CLI Login check
            _sonicwall_cli_login(shell, firewall)

            # Disable CLI pager pagination
            _send_command(shell, "no cli pager", wait=1.0)

            _push_timezone_status(fw_id, "fetching", "Running: show time")
            output_time = _send_command(shell, "show time", wait=2.0)

            # Try to extract date, time, and timezone
            fw_time = ""
            fw_date = ""
            fw_timezone = ""
            for line in output_time.splitlines():
                line_strip = line.strip()
                parts = line_strip.split(None, 1)
                if not parts:
                    continue
                key = parts[0].lower().rstrip(":")
                val = parts[1].strip() if len(parts) > 1 else ""
                if key == "time":
                    if ":" in val:
                        fw_time = val
                elif key == "date":
                    fw_date = val
                elif key == "time-zone":
                    fw_timezone = val

            # Format firewall time & timezone nicely
            if fw_time and fw_timezone:
                time_display = f"{fw_time} ({fw_timezone})"
            elif fw_time:
                time_display = fw_time
            elif fw_timezone:
                time_display = fw_timezone
            else:
                time_display = "Not found"

            # Debug log to workspace for analysis
            try:
                with open("debug_timezone.txt", "w", encoding="utf-8") as df:
                    df.write(f"=== OUTPUT TIME ===\n{output_time}\n")
                    df.write(f"Parsed Time: {fw_time}, Date: {fw_date}, TZ: {fw_timezone}\n")
            except Exception as e:
                logger.warning("Failed to write debug file: %s", e)

            _push_timezone_status(fw_id, "success", message=time_display, fw_time=time_display)

    except paramiko.AuthenticationException:
        _push_timezone_status(fw_id, "failed", "Authentication failed")
    except paramiko.SSHException as exc:
        _push_timezone_status(fw_id, "failed", f"SSH error: {exc}")
    except Exception as exc:
        _push_timezone_status(fw_id, "failed", f"Error: {exc}")
    finally:
        if ssh:
            if shell:
                try:
                    shell.send("exit\n")
                    time.sleep(0.2)
                except Exception:
                    pass
            ssh.close()


# ---------------------------------------------------------------------------
# Schedule Check & Cancel Execution
# ---------------------------------------------------------------------------

def execute_check_schedule(firewall: dict) -> None:
    """SSH into one firewall and retrieve its reboot schedule using 'restart schedule'."""
    fw_id = firewall["id"]
    ip = firewall["ip"]
    _push_schedule_status(fw_id, "checking", f"Waiting for lock on {ip}...")

    ssh = None
    shell = None
    try:
        with firewall_locks[ip]:
            _push_schedule_status(fw_id, "checking", f"Connecting to {ip}...")
            ssh = _ssh_connect(firewall, timeout=15)
            _push_schedule_status(fw_id, "connected", f"Connected to {firewall['name']}")

            shell = ssh.invoke_shell()
            shell.settimeout(10.0)
            _sonicwall_cli_login(shell, firewall)
            _send_command(shell, "no cli pager", wait=1.0)

            _push_schedule_status(fw_id, "fetching", "Running: restart schedule")
            output = _send_command(shell, "restart schedule", wait=3.0)

            # Parse schedule status
            clean = output.strip()
            lines = []
            for line in clean.splitlines():
                line_lower = line.strip().lower()
                # Skip command echo, prompts, and status headers
                if "processing command" in line_lower:
                    continue
                if "restart schedule" in line_lower:
                    continue
                if "admin@" in line_lower:
                    continue
                if not line.strip():
                    continue
                lines.append(line.strip())

            # Join remaining lines for the message
            schedule_text = " ".join(lines)

            # Determine if an active schedule exists
            # In SonicOS, when there is no schedule, it outputs: "% No running restart."
            no_schedule_keywords = [
                "no running", 
                "no schedule", 
                "inactive", 
                "none", 
                "not configured", 
                "not scheduled", 
                "error", 
                "invalid", 
                "access denied", 
                "password", 
                "session timed out"
            ]
            has_schedule = True
            if not schedule_text or any(k in schedule_text.lower() for k in no_schedule_keywords) or "user:" in schedule_text.lower():
                has_schedule = False

            _push_schedule_status(fw_id, "success", schedule_text or "No running restart.", has_schedule=has_schedule)

    except Exception as exc:
        _push_schedule_status(fw_id, "failed", str(exc), has_schedule=False)
    finally:
        if ssh:
            if shell:
                try:
                    shell.send("exit\n")
                    time.sleep(0.2)
                except Exception:
                    pass
            ssh.close()


def execute_cancel_schedule(firewall: dict) -> None:
    """SSH into one firewall and cancel its reboot schedule using 'restart cancel'."""
    fw_id = firewall["id"]
    ip = firewall["ip"]
    _push_schedule_status(fw_id, "cancelling", f"Waiting for lock on {ip}...")

    ssh = None
    shell = None
    try:
        with firewall_locks[ip]:
            _push_schedule_status(fw_id, "cancelling", f"Connecting to {ip}...")
            ssh = _ssh_connect(firewall, timeout=15)
            _push_schedule_status(fw_id, "connected", f"Connected to {firewall['name']}")

            shell = ssh.invoke_shell()
            shell.settimeout(10.0)
            _sonicwall_cli_login(shell, firewall)
            _send_command(shell, "no cli pager", wait=1.0)

            output = _send_command(shell, "restart cancel", wait=3.0)
            clean = output.strip()

            _push_schedule_status(fw_id, "cancelled", clean or "Restart schedule cancelled", has_schedule=False)

    except Exception as exc:
        _push_schedule_status(fw_id, "failed", f"Cancel failed: {exc}", has_schedule=True)
    finally:
        if ssh:
            if shell:
                try:
                    shell.send("exit\n")
                    time.sleep(0.2)
                except Exception:
                    pass
            ssh.close()


def _schedule_worker(firewalls: list, action: str, batch_size: int) -> None:
    global is_schedule_running, schedule_cancel_flag
    logger.info("Schedule worker: %d firewalls, action=%s, batch=%d", len(firewalls), action, batch_size)
    try:
        for i in range(0, len(firewalls), batch_size):
            with schedule_lock:
                if schedule_cancel_flag:
                    for fw in firewalls[i:]:
                        _push_schedule_status(fw["id"], "cancelled", "Cancelled")
                    break

            batch = firewalls[i : i + batch_size]
            threads = []
            for fw in batch:
                target_fn = execute_check_schedule if action == "check" else execute_cancel_schedule
                t = threading.Thread(target=target_fn, args=(fw,), daemon=True)
                threads.append(t)
                t.start()
            for t in threads:
                t.join()

        _push_schedule_status("-1", "complete", "Done")
    finally:
        with schedule_lock:
            is_schedule_running = False
            schedule_cancel_flag = False
        logger.info("Schedule worker finished")

# ---------------------------------------------------------------------------
# Background Workers

# ---------------------------------------------------------------------------

def _reboot_worker(firewalls: list, batch_size: int) -> None:
    global is_running, cancel_flag
    logger.info("Reboot worker: %d firewalls, batch=%d", len(firewalls), batch_size)
    try:
        for i in range(0, len(firewalls), batch_size):
            with state_lock:
                if cancel_flag:
                    for fw in firewalls[i:]:
                        _push_reboot_status(fw["id"], "cancelled", "Cancelled by user")
                    break

            batch = firewalls[i : i + batch_size]
            threads = []
            for fw in batch:
                with state_lock:
                    if cancel_flag:
                        _push_reboot_status(fw["id"], "cancelled", "Cancelled by user")
                        continue
                t = threading.Thread(target=execute_reboot, args=(fw,), daemon=True)
                threads.append(t)
                t.start()
            for t in threads:
                t.join()

        _push_reboot_status("-1", "complete", "Done")
    finally:
        with state_lock:
            is_running = False
            cancel_flag = False
        logger.info("Reboot worker finished")


def _uptime_worker(firewalls: list, batch_size: int) -> None:
    global is_uptime_running, uptime_cancel_flag
    logger.info("Uptime worker: %d firewalls, batch=%d", len(firewalls), batch_size)
    try:
        for i in range(0, len(firewalls), batch_size):
            with uptime_lock:
                if uptime_cancel_flag:
                    for fw in firewalls[i:]:
                        _push_uptime_status(fw["id"], "cancelled", "Cancelled")
                    break

            batch = firewalls[i : i + batch_size]
            threads = []
            for fw in batch:
                t = threading.Thread(target=execute_uptime, args=(fw,), daemon=True)
                threads.append(t)
                t.start()
            for t in threads:
                t.join()

        _push_uptime_status("-1", "complete", "Done")
    finally:
        with uptime_lock:
            is_uptime_running = False
            uptime_cancel_flag = False
        logger.info("Uptime worker finished")


def _timezone_worker(firewalls: list, batch_size: int) -> None:
    global is_timezone_running, timezone_cancel_flag
    logger.info("Timezone worker: %d firewalls, batch=%d", len(firewalls), batch_size)
    try:
        for i in range(0, len(firewalls), batch_size):
            with timezone_lock:
                if timezone_cancel_flag:
                    for fw in firewalls[i:]:
                        _push_timezone_status(fw["id"], "cancelled", "Cancelled")
                    break

            batch = firewalls[i : i + batch_size]
            threads = []
            for fw in batch:
                t = threading.Thread(target=execute_timezone, args=(fw,), daemon=True)
                threads.append(t)
                t.start()
            for t in threads:
                t.join()

        _push_timezone_status("-1", "complete", "Done")
    finally:
        with timezone_lock:
            is_timezone_running = False
            timezone_cancel_flag = False
        logger.info("Timezone worker finished")

# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/upload-csv", methods=["POST"])
def upload_csv():
    """Parse CSV: Name, IP, Port, Username, Password, Site."""
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    try:
        stream = io.StringIO(file.stream.read().decode("utf-8-sig"))
        reader = csv.DictReader(stream)
        if reader.fieldnames is None:
            return jsonify({"error": "CSV is empty"}), 400

        header_map = {h.strip().lower(): h for h in reader.fieldnames}
        required = {"name", "ip", "port", "username", "password", "site"}
        missing = required - set(header_map.keys())
        if missing:
            return jsonify({"error": f"Missing columns: {', '.join(missing)}"}), 400

        firewalls = []
        for idx, row in enumerate(reader):
            firewalls.append({
                "id": str(uuid.uuid4()),
                "index": idx,
                "name": row[header_map["name"]].strip(),
                "ip": row[header_map["ip"]].strip(),
                "port": row[header_map["port"]].strip() or "22",
                "username": row[header_map["username"]].strip(),
                "password": row[header_map["password"]].strip(),
                "site": row[header_map["site"]].strip(),
            })

        logger.info("CSV: %d firewalls parsed", len(firewalls))
        return jsonify({"firewalls": firewalls, "count": len(firewalls)})
    except Exception as exc:
        logger.exception("CSV parse error")
        return jsonify({"error": f"CSV parse failed: {exc}"}), 400


@app.route("/api/schedule-reboot", methods=["POST"])
def schedule_reboot():
    """Start batch reboot. Each firewall has its own mode & datetime."""
    global is_running, cancel_flag

    with state_lock:
        if is_running:
            return jsonify({"error": "Already running"}), 409

    data = request.get_json(force=True)
    firewalls = data.get("firewalls", [])
    batch_size = int(data.get("batchSize", 10))

    if not firewalls:
        return jsonify({"error": "No firewalls"}), 400

    # Each firewall should have: id, name, ip, port, username, password, mode, datetime
    with state_lock:
        is_running = True
        cancel_flag = False
        current_status.clear()

    while not status_queue.empty():
        try:
            status_queue.get_nowait()
        except queue.Empty:
            break

    t = threading.Thread(target=_reboot_worker, args=(firewalls, batch_size), daemon=True)
    t.start()
    logger.info("Reboot started: %d firewalls", len(firewalls))
    return jsonify({"message": "Started", "total": len(firewalls)})


@app.route("/api/status", methods=["GET"])
def status_stream():
    """SSE stream for reboot status."""
    def generate():
        last_hb = time.time()
        while True:
            try:
                event = status_queue.get(timeout=1)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("id") == "-1" and event.get("status") == "complete":
                    break
            except queue.Empty:
                if time.time() - last_hb >= 30:
                    yield f": heartbeat {datetime.now().isoformat()}\n\n"
                    last_hb = time.time()
                with state_lock:
                    if not is_running:
                        break

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/get-uptime", methods=["POST"])
def get_uptime():
    """Start batch uptime check."""
    global is_uptime_running, uptime_cancel_flag

    with uptime_lock:
        if is_uptime_running:
            return jsonify({"error": "Uptime check already running"}), 409

    data = request.get_json(force=True)
    firewalls = data.get("firewalls", [])
    batch_size = int(data.get("batchSize", 10))

    if not firewalls:
        return jsonify({"error": "No firewalls"}), 400

    with uptime_lock:
        is_uptime_running = True
        uptime_cancel_flag = False

    while not uptime_queue.empty():
        try:
            uptime_queue.get_nowait()
        except queue.Empty:
            break

    t = threading.Thread(target=_uptime_worker, args=(firewalls, batch_size), daemon=True)
    t.start()
    logger.info("Uptime check started: %d firewalls", len(firewalls))
    return jsonify({"message": "Started", "total": len(firewalls)})


@app.route("/api/uptime-status", methods=["GET"])
def uptime_stream():
    """SSE stream for uptime status."""
    def generate():
        last_hb = time.time()
        while True:
            try:
                event = uptime_queue.get(timeout=1)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("id") == "-1" and event.get("status") == "complete":
                    break
            except queue.Empty:
                if time.time() - last_hb >= 30:
                    yield f": heartbeat\n\n"
                    last_hb = time.time()
                with uptime_lock:
                    if not is_uptime_running:
                        break

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/get-timezone", methods=["POST"])
def get_timezone():
    """Start batch timezone check."""
    global is_timezone_running, timezone_cancel_flag

    with timezone_lock:
        if is_timezone_running:
            return jsonify({"error": "Timezone check already running"}), 409

    data = request.get_json(force=True)
    firewalls = data.get("firewalls", [])
    batch_size = int(data.get("batchSize", 10))

    if not firewalls:
        return jsonify({"error": "No firewalls"}), 400

    with timezone_lock:
        is_timezone_running = True
        timezone_cancel_flag = False

    while not timezone_queue.empty():
        try:
            timezone_queue.get_nowait()
        except queue.Empty:
            break

    t = threading.Thread(target=_timezone_worker, args=(firewalls, batch_size), daemon=True)
    t.start()
    logger.info("Timezone check started: %d firewalls", len(firewalls))
    return jsonify({"message": "Started", "total": len(firewalls)})


@app.route("/api/timezone-status", methods=["GET"])
def timezone_stream():
    """SSE stream for timezone status."""
    def generate():
        last_hb = time.time()
        while True:
            try:
                event = timezone_queue.get(timeout=1)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("id") == "-1" and event.get("status") == "complete":
                    break
            except queue.Empty:
                if time.time() - last_hb >= 30:
                    yield f": heartbeat\n\n"
                    last_hb = time.time()
                with timezone_lock:
                    if not is_timezone_running:
                        break

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})



@app.route("/api/cancel", methods=["POST"])
def cancel():
    global cancel_flag
    with state_lock:
        cancel_flag = True
    logger.info("Cancel signal sent")
    return jsonify({"message": "Cancel signal sent"})


@app.route("/api/cancel-uptime", methods=["POST"])
def cancel_uptime():
    global uptime_cancel_flag
    with uptime_lock:
        uptime_cancel_flag = True
    return jsonify({"message": "Uptime cancel signal sent"})


@app.route("/api/check-schedule", methods=["POST"])
def check_schedule():
    """Start batch schedule check."""
    global is_schedule_running, schedule_cancel_flag

    with schedule_lock:
        if is_schedule_running:
            return jsonify({"error": "Schedule operation already running"}), 409

    data = request.get_json(force=True)
    firewalls = data.get("firewalls", [])
    batch_size = int(data.get("batchSize", 10))

    if not firewalls:
        return jsonify({"error": "No firewalls"}), 400

    with schedule_lock:
        is_schedule_running = True
        schedule_cancel_flag = False

    while not schedule_queue.empty():
        try:
            schedule_queue.get_nowait()
        except queue.Empty:
            break

    t = threading.Thread(target=_schedule_worker, args=(firewalls, "check", batch_size), daemon=True)
    t.start()
    logger.info("Schedule check started: %d firewalls", len(firewalls))
    return jsonify({"message": "Started", "total": len(firewalls)})


@app.route("/api/cancel-schedule", methods=["POST"])
def cancel_schedule():
    """Start batch schedule cancel."""
    global is_schedule_running, schedule_cancel_flag

    with schedule_lock:
        if is_schedule_running:
            return jsonify({"error": "Schedule operation already running"}), 409

    data = request.get_json(force=True)
    firewalls = data.get("firewalls", [])
    batch_size = int(data.get("batchSize", 10))

    if not firewalls:
        return jsonify({"error": "No firewalls"}), 400

    with schedule_lock:
        is_schedule_running = True
        schedule_cancel_flag = False

    while not schedule_queue.empty():
        try:
            schedule_queue.get_nowait()
        except queue.Empty:
            break

    t = threading.Thread(target=_schedule_worker, args=(firewalls, "cancel", batch_size), daemon=True)
    t.start()
    logger.info("Schedule cancel started: %d firewalls", len(firewalls))
    return jsonify({"message": "Started", "total": len(firewalls)})


@app.route("/api/schedule-status", methods=["GET"])
def schedule_stream():
    """SSE stream for schedule status (check & cancel)."""
    def generate():
        last_hb = time.time()
        while True:
            try:
                event = schedule_queue.get(timeout=1)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("id") == "-1" and event.get("status") == "complete":
                    break
            except queue.Empty:
                if time.time() - last_hb >= 30:
                    yield f": heartbeat\n\n"
                    last_hb = time.time()
                with schedule_lock:
                    if not is_schedule_running:
                        break

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/running", methods=["GET"])
def running():
    with state_lock:
        r = is_running
    with uptime_lock:
        u = is_uptime_running
    with schedule_lock:
        s = is_schedule_running
    return jsonify({"running": r, "uptimeRunning": u, "scheduleRunning": s})


@app.route("/api/settings", methods=["GET"])
def get_settings():
    settings = _load_settings()
    # Mask password for security
    masked_settings = settings.copy()
    if masked_settings.get("smtp_password"):
        masked_settings["smtp_password"] = "********"
    return jsonify(masked_settings)


@app.route("/api/settings", methods=["POST"])
def update_settings():
    data = request.get_json(force=True)
    current = _load_settings()
    
    # Only update password if it's not the masked value
    password = data.get("smtp_password", "")
    if password == "********":
        data["smtp_password"] = current.get("smtp_password", "")
        
    # Cast port and monitoring timeout to correct types
    try:
        data["smtp_port"] = int(data.get("smtp_port", 587))
    except ValueError:
        data["smtp_port"] = 587
        
    try:
        data["monitoring_timeout_minutes"] = int(data.get("monitoring_timeout_minutes", 10))
    except ValueError:
        data["monitoring_timeout_minutes"] = 10
        
    if _save_settings(data):
        return jsonify({"message": "Settings saved successfully"})
    return jsonify({"error": "Failed to save settings"}), 500


@app.route("/api/settings/test-email", methods=["POST"])
def test_email():
    data = request.get_json(force=True)
    current = _load_settings()
    
    password = data.get("smtp_password", "")
    if password == "********":
        data["smtp_password"] = current.get("smtp_password", "")
        
    try:
        data["smtp_port"] = int(data.get("smtp_port", 587))
    except ValueError:
        data["smtp_port"] = 587
        
    try:
        data["monitoring_timeout_minutes"] = int(data.get("monitoring_timeout_minutes", 10))
    except ValueError:
        data["monitoring_timeout_minutes"] = 10
        
    # Temporarily override settings to test
    orig_settings = _load_settings()
    _save_settings(data)
    
    subject = "[Maintenance Alert] Test Email Notification"
    body = (
        "This is a test notification email from your Firewall Reboot Scheduler.\n\n"
        "If you received this message, your SMTP settings are configured correctly."
    )
    # Enable emails temporarily for test email sending
    data["enable_emails"] = True
    _save_settings(data)
    
    success = _send_notification_email(subject, body)
    
    # Restore original settings
    _save_settings(orig_settings)
    
    if success:
        return jsonify({"message": "Test email sent successfully!"})
    return jsonify({"error": "Failed to send test email. Check server logs."}), 500


# ---------------------------------------------------------------------------
# AES-256-GCM Secure Encryption & Decryption Endpoints (PyCA Cryptography)
# OWASP 2023 Hardened: 600,000 PBKDF2 iterations, 32-byte salts, 12-char min
# ---------------------------------------------------------------------------

ENCRYPT_ITERATIONS = 600000   # OWASP 2023 recommendation for PBKDF2-SHA256
ENCRYPT_SALT_BYTES = 32       # 256-bit salt
ENCRYPT_IV_BYTES = 12         # 96-bit IV (GCM standard)
MIN_PASSPHRASE_LEN = 12       # Minimum passphrase length

def _secure_zero(buf):
    """Overwrite a mutable buffer (bytearray/memoryview) with null bytes in-place."""
    if isinstance(buf, (bytearray, memoryview)):
        for i in range(len(buf)):
            buf[i] = 0

def _derive_aes_key(passphrase: str, salt: bytes, iterations: int = ENCRYPT_ITERATIONS) -> bytes:
    """Derive AES-256 key from passphrase using PBKDF2. Uses bytearray for secure wiping."""
    pass_bytes = bytearray(passphrase.encode("utf-8"))
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        key = kdf.derive(bytes(pass_bytes))
        return key
    finally:
        _secure_zero(pass_bytes)
        del pass_bytes

def _validate_passphrase(passphrase: str) -> str:
    """Validate passphrase meets security requirements. Returns error message or empty string."""
    if not passphrase or len(passphrase) < MIN_PASSPHRASE_LEN:
        return f"Passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
    if not any(c.isupper() for c in passphrase):
        return "Passphrase must contain at least one uppercase letter"
    if not any(c.islower() for c in passphrase):
        return "Passphrase must contain at least one lowercase letter"
    if not any(c.isdigit() for c in passphrase):
        return "Passphrase must contain at least one digit"
    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?/~`' for c in passphrase):
        return "Passphrase must contain at least one special character (!@#$%^&*...)"
    return ""


@app.route("/api/encrypt-csv", methods=["POST"])
def encrypt_csv_endpoint():
    """Encrypt raw CSV text using AES-256-GCM and PBKDF2 (600,000 rounds, OWASP 2023)."""
    key = passphrase = csv_text = ciphertext = None
    try:
        data = request.get_json() or {}
        csv_text = data.get("csv_text", "").strip()
        passphrase = data.get("passphrase", "").strip()

        if not csv_text:
            return jsonify({"error": "CSV content is empty"}), 400
        pass_err = _validate_passphrase(passphrase)
        if pass_err:
            return jsonify({"error": pass_err}), 400

        salt = os.urandom(ENCRYPT_SALT_BYTES)
        iv = os.urandom(ENCRYPT_IV_BYTES)
        key = _derive_aes_key(passphrase, salt)
        aesgcm = AESGCM(key)
        aad = f"v2|AES-256-GCM|PBKDF2-SHA256|{ENCRYPT_ITERATIONS}".encode("utf-8")
        ciphertext = aesgcm.encrypt(iv, csv_text.encode("utf-8"), aad)

        payload = {
            "v": 2,
            "algo": "AES-256-GCM",
            "kdf": "PBKDF2-SHA256",
            "iterations": ENCRYPT_ITERATIONS,
            "salt": salt.hex(),
            "iv": iv.hex(),
            "data": ciphertext.hex(),
        }
        return jsonify({"ok": True, "enc_payload": payload, "json_str": json.dumps(payload)})
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        return jsonify({"error": f"Encryption failed: {str(e)}"}), 500
    finally:
        # Memory-safe: wipe sensitive variables and force garbage collection
        del key, passphrase, csv_text, ciphertext
        gc.collect()


@app.route("/api/export-enc", methods=["POST"])
def export_enc_file_endpoint():
    """Returns downloadable AES-256 .enc file attachment (OWASP 2023 hardened)."""
    key = passphrase = csv_text = ciphertext = None
    try:
        data = request.get_json() or {}
        csv_text = data.get("csv_text", "").strip()
        passphrase = data.get("passphrase", "").strip()
        filename = data.get("filename", "inventory.csv")

        if not csv_text:
            return jsonify({"error": "CSV content is empty"}), 400
        pass_err = _validate_passphrase(passphrase)
        if pass_err:
            return jsonify({"error": pass_err}), 400

        salt = os.urandom(ENCRYPT_SALT_BYTES)
        iv = os.urandom(ENCRYPT_IV_BYTES)
        key = _derive_aes_key(passphrase, salt)
        aesgcm = AESGCM(key)
        aad = f"v2|AES-256-GCM|PBKDF2-SHA256|{ENCRYPT_ITERATIONS}".encode("utf-8")
        ciphertext = aesgcm.encrypt(iv, csv_text.encode("utf-8"), aad)

        payload = {
            "v": 2,
            "algo": "AES-256-GCM",
            "kdf": "PBKDF2-SHA256",
            "iterations": ENCRYPT_ITERATIONS,
            "salt": salt.hex(),
            "iv": iv.hex(),
            "data": ciphertext.hex(),
        }
        json_bytes = json.dumps(payload, indent=2).encode("utf-8")
        out_filename = filename.rsplit(".", 1)[0] + "_encrypted.enc"

        return Response(
            json_bytes,
            mimetype="application/json",
            headers={
                "Content-Disposition": f"attachment; filename={out_filename}",
                "Access-Control-Expose-Headers": "Content-Disposition",
            },
        )
    except Exception as e:
        logger.error(f"Export ENC error: {e}")
        return jsonify({"error": f"Export failed: {str(e)}"}), 500
    finally:
        del key, passphrase, csv_text, ciphertext
        gc.collect()


@app.route("/api/decrypt-csv", methods=["POST"])
def decrypt_csv_endpoint():
    """Decrypt AES-256-GCM .enc payload using PBKDF2 derived key (v1 & v2 compatible)."""
    key = passphrase = decrypted_bytes = csv_text = None
    try:
        data = request.get_json() or {}
        enc_str = data.get("enc_str", "").strip()
        passphrase = data.get("passphrase", "").strip()

        if not enc_str:
            return jsonify({"error": "Encrypted file payload is empty"}), 400
        if not passphrase:
            return jsonify({"error": "Passphrase is required"}), 400

        payload = json.loads(enc_str)
        salt = bytes.fromhex(payload["salt"])
        iv = bytes.fromhex(payload["iv"])
        ciphertext = bytes.fromhex(payload["data"])
        iterations = payload.get("iterations", 100000)
        version = payload.get("v", 1)

        key = _derive_aes_key(passphrase, salt, iterations)
        aesgcm = AESGCM(key)

        # v2 payloads use AAD header binding; v1 payloads use None (backward compatible)
        aad = None
        if version >= 2:
            aad = f"v{version}|{payload.get('algo', 'AES-256-GCM')}|{payload.get('kdf', 'PBKDF2-SHA256')}|{iterations}".encode("utf-8")

        decrypted_bytes = aesgcm.decrypt(iv, ciphertext, aad)
        csv_text = decrypted_bytes.decode("utf-8")

        return jsonify({"ok": True, "csv_text": csv_text})
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        return jsonify({"error": "Decryption failed. Incorrect passphrase or corrupted payload."}), 400
    finally:
        del key, passphrase, decrypted_bytes, csv_text
        gc.collect()


@app.route("/api/clear", methods=["POST"])
def clear_in_memory_state():
    """Wipe any transient cached execution or status results in server memory."""
    try:
        global current_status, cancel_flag, uptime_cancel_flag, timezone_cancel_flag, schedule_cancel_flag
        with state_lock:
            current_status.clear()
            cancel_flag = False
        with uptime_lock:
            uptime_cancel_flag = False
        with timezone_lock:
            timezone_cancel_flag = False
        with schedule_lock:
            schedule_cancel_flag = False
        logger.info("Cleared in-memory state")
        return jsonify({"message": "In-memory state cleared successfully"})
    except Exception as e:
        logger.error(f"Error clearing state: {e}")
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    use_dev = "--dev" in sys.argv
    
    if use_dev:
        logger.info("Starting Firewall Reboot Scheduler API in Development Mode on port 5000")
        app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)
    else:
        logger.info("Starting Firewall Reboot Scheduler API in Production Mode (Waitress WSGI) on http://0.0.0.0:5000")
        try:
            from waitress import serve
            serve(app, host="0.0.0.0", port=5000, threads=16)
        except ImportError:
            logger.warning("Waitress not installed. Falling back to Flask dev server.")
            app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)

