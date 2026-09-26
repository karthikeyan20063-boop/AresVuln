import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from urllib.parse import urlparse, urljoin, quote
import requests
import socket
import threading
import queue
import time

# ============================================================
# AresVuln - Beginner Web Security Scanner
# Use ONLY on systems you own or are explicitly authorized to test.
# This version removes destructive payloads and uses safer checks.
# ============================================================

COMMON_PORTS = [21, 22, 80, 443, 3306, 8080, 8443]

# Non-destructive SQLi indicators for an authorized lab.
SQL_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR 1=1--",
]

# Harmless XSS marker. It does NOT execute JavaScript.
XSS_MARKER = "AresVuln_XSS_TEST_123"

SENSITIVE_PATHS = [
    "/robots.txt",
    "/.git/",
    "/.env",
    "/config.php",
    "/backup.zip",
]

COMMON_DIRECTORIES = [
    "admin",
    "login",
    "dashboard",
    "uploads",
    "config",
    "images",
]

SUBDOMAINS = [
    "www",
    "test",
    "dev",
    "staging",
    "mail",
    "ftp",
]

TIMEOUT = 5

# GUI-safe message queue. Worker threads never modify Tkinter directly.
log_queue = queue.Queue()


def log_message(message):
    """Send a message from any thread to the GUI."""
    log_queue.put(str(message))


def process_log_queue():
    """Move queued messages into the Tkinter text box."""
    try:
        while True:
            message = log_queue.get_nowait()
            output_area.insert(tk.END, message + "\n")
            output_area.see(tk.END)
    except queue.Empty:
        pass

    root.after(100, process_log_queue)


def normalize_url(value):
    """Make sure the target has http:// or https://."""
    value = value.strip()

    if not value:
        raise ValueError("Please enter a target URL.")

    if not value.startswith(("http://", "https://")):
        value = "http://" + value

    parsed = urlparse(value)

    if not parsed.hostname:
        raise ValueError("Invalid target URL.")

    # Remove a trailing slash so urljoin behaves consistently.
    return value.rstrip("/")


def get_host(url):
    """Return only the hostname from a URL."""
    return urlparse(url).hostname


def make_session():
    session = requests.Session()
    session.headers.update({
        "User-Agent": "AresVuln-AuthorizedScanner/1.0"
    })
    return session


# ============================================================
# PORT SCANNING
# ============================================================

def scan_ports(host):
    log_message("\n[+] Scanning common TCP ports...")

    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        try:
            result = sock.connect_ex((host, port))

            if result == 0:
                log_message(f"    [OPEN] TCP {port}")
            else:
                log_message(f"    [CLOSED/FILTERED] TCP {port}")

        except socket.gaierror:
            log_message(f"    [ERROR] Could not resolve host: {host}")
            break

        except OSError as exc:
            log_message(f"    [ERROR] Port {port}: {exc}")

        finally:
            sock.close()


# ============================================================
# HTTP SECURITY HEADERS
# ============================================================

def check_security_headers(session, url):
    log_message("\n[+] Checking HTTP security headers...")

    try:
        response = session.get(url, timeout=TIMEOUT, allow_redirects=True)

        security_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Content-Type-Options": "X-Content-Type-Options",
            "X-Frame-Options": "Clickjacking protection",
            "Referrer-Policy": "Referrer-Policy",
        }

        for header, description in security_headers.items():
            if header in response.headers:
                log_message(f"    [PRESENT] {description}")
            else:
                log_message(f"    [MISSING] {description}")

        log_message(f"    [INFO] HTTP status: {response.status_code}")
        log_message(f"    [INFO] Final URL: {response.url}")

    except requests.RequestException as exc:
        log_message(f"    [ERROR] {exc}")


# ============================================================
# SQL INJECTION TEST
# ============================================================

def test_sql_injection(session, url):
    log_message("\n[+] Testing basic SQL injection indicators...")

    parsed = urlparse(url)

    # This scanner assumes an "id" parameter for demonstration.
    base = url.split("?", 1)[0]

    for payload in SQL_PAYLOADS:
        try:
            response = session.get(
                base,
                params={"id": payload},
                timeout=TIMEOUT,
                allow_redirects=False,
            )

            body = response.text.lower()

            error_words = [
                "sql syntax",
                "mysql",
                "mysqli",
                "postgresql",
                "sqlite",
                "ora-",
                "odbc",
                "database error",
            ]

            if any(word in body for word in error_words):
                log_message(
                    f"    [POSSIBLE] SQL error indicator with payload: {payload}"
                )
            else:
                log_message(f"    [INFO] No obvious SQL error for: {payload}")

        except requests.RequestException as exc:
            log_message(f"    [ERROR] SQL test: {exc}")


# ============================================================
# REFLECTED INPUT TEST
# ============================================================

def test_reflection(session, url):
    log_message("\n[+] Testing reflected input...")

    base = url.split("?", 1)[0]

    try:
        response = session.get(
            base,
            params={"q": XSS_MARKER},
            timeout=TIMEOUT,
            allow_redirects=False,
        )

        if XSS_MARKER in response.text:
            log_message(
                "    [POSSIBLE] User input was reflected in the response."
            )
            log_message(
                "    [NOTE] Reflection alone does not prove XSS."
            )
        else:
            log_message("    [OK] Test marker was not reflected.")

    except requests.RequestException as exc:
        log_message(f"    [ERROR] Reflection test: {exc}")


# ============================================================
# SENSITIVE FILE CHECK
# ============================================================

def check_sensitive_files(session, url):
    log_message("\n[+] Checking common sensitive paths...")

    for path in SENSITIVE_PATHS:
        target = urljoin(url + "/", path.lstrip("/"))

        try:
            response = session.get(
                target,
                timeout=TIMEOUT,
                allow_redirects=False,
            )

            if response.status_code == 200:
                log_message(
                    f"    [FOUND/REVIEW] {target} -> HTTP 200"
                )
            elif response.status_code in (301, 302, 307, 308):
                log_message(
                    f"    [REDIRECT] {target} -> HTTP {response.status_code}"
                )

        except requests.RequestException:
            pass


# ============================================================
# DIRECTORY DISCOVERY
# ============================================================

def directory_scan(session, url):
    log_message("\n[+] Checking common directories...")

    for directory in COMMON_DIRECTORIES:
        target = urljoin(url + "/", directory + "/")

        try:
            response = session.get(
                target,
                timeout=TIMEOUT,
                allow_redirects=False,
            )

            if response.status_code in (200, 204, 301, 302, 307, 308):
                log_message(
                    f"    [FOUND/REVIEW] {target} -> HTTP {response.status_code}"
                )

        except requests.RequestException:
            pass


# ============================================================
# SUBDOMAIN CHECK
# ============================================================

def subdomain_scan(domain):
    log_message("\n[+] Checking common subdomains...")

    for subdomain in SUBDOMAINS:
        hostname = f"{subdomain}.{domain}"

        try:
            socket.gethostbyname(hostname)
            log_message(f"    [RESOLVES] {hostname}")

        except socket.gaierror:
            pass


# ============================================================
# BASIC OPEN REDIRECT CHECK
# ============================================================

def test_open_redirect(session, url):
    log_message("\n[+] Testing basic redirect behavior...")

    base = url.split("?", 1)[0]

    # A harmless external-looking value is used only as a marker.
    marker = "https://example.com/aresvuln-test"

    try:
        response = session.get(
            base,
            params={"next": marker},
            timeout=TIMEOUT,
            allow_redirects=False,
        )

        location = response.headers.get("Location", "")

        if response.status_code in (301, 302, 303, 307, 308):
            if marker in location:
                log_message(
                    "    [POSSIBLE] Redirect parameter controls Location."
                )
            else:
                log_message("    [INFO] Redirect detected; Location did not match marker.")
        else:
            log_message("    [OK] No redirect observed for the test.")

    except requests.RequestException as exc:
        log_message(f"    [ERROR] Redirect test: {exc}")


# ============================================================
# MAIN SCAN
# ============================================================

def run_scans(target, host):
    start_time = time.time()

    try:
        session = make_session()

        log_message(f"\n=== AresVuln Scan ===")
        log_message(f"Target: {target}")
        log_message(f"Host:   {host}")

        scan_ports(host)
        check_security_headers(session, target)
        test_sql_injection(session, target)
        test_reflection(session, target)
        check_sensitive_files(session, target)
        directory_scan(session, target)
        subdomain_scan(host)
        test_open_redirect(session, target)

        elapsed = time.time() - start_time
        log_message(f"\n[+] Scan complete in {elapsed:.1f} seconds.")

    except Exception as exc:
        log_message(f"\n[ERROR] Scan stopped: {exc}")


def start_scan():
    try:
        target = normalize_url(url_entry.get())
        host = get_host(target)

        if not host:
            raise ValueError("Could not determine hostname.")

        log_message(f"\n[>] Starting scan for {target}")

        # Disable button while the scan is running.
        scan_btn.config(state=tk.DISABLED)

        worker = threading.Thread(
            target=run_scan_and_reenable,
            args=(target, host),
            daemon=True,
        )
        worker.start()

    except ValueError as exc:
        messagebox.showerror("Invalid Target", str(exc))


def run_scan_and_reenable(target, host):
    run_scans(target, host)

    # Tkinter updates must happen in the GUI thread.
    root.after(0, lambda: scan_btn.config(state=tk.NORMAL))


# ============================================================
# REPORT
# ============================================================

def export_report():
    report_text = output_area.get("1.0", tk.END).strip()

    if not report_text:
        messagebox.showinfo("Report", "There are no scan results to export.")
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt")],
        title="Save AresVuln Report",
    )

    if file_path:
        try:
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(report_text)

            log_message(f"\n[+] Report saved: {file_path}")

        except OSError as exc:
            messagebox.showerror("Save Error", str(exc))


def clear_terminal():
    output_area.delete("1.0", tk.END)


# ============================================================
# GUI
# ============================================================

root = tk.Tk()
root.title("AresVuln - Web Security Scanner")
root.geometry("1000x760")
root.configure(bg="black")

TERMINAL_FONT = ("Consolas", 11)
TITLE_FONT = ("Consolas", 20, "bold")


def create_hacker_button(parent, text, command):
    button = tk.Button(
        parent,
        text=text,
        font=("Consolas", 11, "bold"),
        bg="black",
        fg="#11FFC0",
        activebackground="#11FFC0",
        activeforeground="black",
        relief=tk.FLAT,
        bd=2,
        highlightthickness=1,
        highlightbackground="#11FFC0",
        cursor="hand2",
        padx=18,
        pady=8,
        command=command,
    )

    def on_enter(_event):
        button.config(bg="#11FFC0", fg="black")

    def on_leave(_event):
        button.config(bg="black", fg="#11FFC0")

    button.bind("<Enter>", on_enter)
    button.bind("<Leave>", on_leave)

    return button


title = tk.Label(
    root,
    text="ARES VULN",
    font=TITLE_FONT,
    bg="black",
    fg="#11FFC0",
)
title.pack(pady=(15, 5))

url_label = tk.Label(
    root,
    text="Target URL:",
    font=TERMINAL_FONT,
    bg="black",
    fg="#11FFC0",
)
url_label.pack(pady=5)

url_entry = tk.Entry(
    root,
    font=TERMINAL_FONT,
    width=65,
    bg="black",
    fg="#11FFC0",
    insertbackground="#11FFC0",
)
url_entry.pack(pady=5)

# Example target for a local lab.
url_entry.insert(0, "http://127.0.0.1:5000")

btn_frame = tk.Frame(root, bg="black")
btn_frame.pack(pady=12)

scan_btn = create_hacker_button(
    btn_frame,
    "START SCAN",
    start_scan,
)
scan_btn.grid(row=0, column=0, padx=8)

export_btn = create_hacker_button(
    btn_frame,
    "EXPORT REPORT",
    export_report,
)
export_btn.grid(row=0, column=1, padx=8)

clear_btn = create_hacker_button(
    btn_frame,
    "CLEAR",
    clear_terminal,
)
clear_btn.grid(row=0, column=2, padx=8)

output_area = scrolledtext.ScrolledText(
    root,
    font=TERMINAL_FONT,
    width=115,
    height=34,
    bg="black",
    fg="#11FFC0",
    insertbackground="#11FFC0",
)
output_area.pack(padx=12, pady=10, fill=tk.BOTH, expand=True)

footer = tk.Label(
    root,
    text="AUTHORIZED SECURITY TESTING ONLY",
    font=("Consolas", 10, "bold"),
    bg="black",
    fg="#11FFC0",
)
footer.pack(side=tk.BOTTOM, pady=8)

# Start processing messages from worker threads.
root.after(100, process_log_queue)

root.mainloop()
