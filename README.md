🛡️ AresVuln – Web Vulnerability Assessment & Security Scanner

AresVuln is a Python-based web security assessment tool designed to perform basic, non-destructive security checks against web applications and authorized systems.

It provides a simple Tkinter-based graphical interface where users can enter a target URL, run multiple security checks, view scan results, and export the results as a text report.
⚠️ Authorized Security Testing Only:
Use AresVuln only against systems that you own or have explicit permission to test. Unauthorized security testing may be illegal.

📌 Project Overview:

AresVuln combines several basic security assessment techniques into a single desktop application.

The scanner currently performs:

🔍 Common TCP port scanning
🛡️ HTTP security-header analysis
💉 Basic SQL injection indicator testing
🌐 Reflected-input testing
📁 Sensitive-path checking
📂 Common-directory discovery
🌍 Common-subdomain checking
🔄 Basic open-redirect testing
📄 Scan-result report export

🎯 Objectives

The main objectives of AresVuln are to:

1.Provide a simple security-scanning interface for beginners.
2.Identify common web-security configuration issues.
3.Perform basic network and HTTP security checks.
4.Display scan results in an easy-to-understand format.
5.Provide an exportable scan report.
6.Help students understand practical web-security assessment concepts.


🛠️ Technologies Used
Technology	-    Purpose
Python	    -    Core programming language
Tkinter	    -    Graphical User Interface
Requests	  -    HTTP requests and web testing
Socket	    -    TCP port and DNS checks
Threading	  -    Background scan execution
Queue	      -    Communication between scanner threads and GUI
HTTP/HTTPS	-    Web application assessment

🔎 Security Checks
1. TCP Port Scanning

AresVuln checks a predefined list of common TCP ports, including:

21    FTP
22    SSH
80    HTTP
443   HTTPS
3306  MySQL
8080  HTTP Alternative
8443  HTTPS Alternative

HTTP Security Headers

2. The scanner checks for commonly recommended HTTP security headers:

Strict-Transport-Security
Content-Security-Policy
X-Content-Type-Options
X-Frame-Options
Referrer-Policy

3. SQL Injection Indicators

AresVuln performs basic, non-destructive SQL injection indicator checks using predefined test inputs.

The current implementation looks for database-related error indicators such as:

SQL syntax
MySQL
PostgreSQL
SQLite
Oracle
ODBC
Database error

4. Reflected Input Testing

The scanner sends a harmless test marker and checks whether it is reflected in the HTTP response.

Example marker:
AresVuln_XSS_TEST_123
Reflection may indicate that further manual testing is required.

5. Sensitive Path Checking

AresVuln checks several commonly exposed paths, including:

/robots.txt
/.git/
/.env
/config.php
/backup.zip
HTTP responses are reported for further investigation.

6. Directory Discovery

The scanner checks common directories such as:

/admin/
/login/
/dashboard/
/uploads/
/config/
/images/
Potentially accessible locations are displayed in the scan output.

7. Subdomain Checking

AresVuln checks common subdomain names such as:

www
test
dev
staging
mail
ftp

8. Basic Open Redirect Check

The scanner tests whether a next parameter appears to control the HTTP Location header.

A positive result is reported as:
[POSSIBLE] Redirect parameter controls Location.

🖥️ Application Interface

The application provides a terminal-style graphical interface containing:

*Target URL input
*Start Scan button
*Export Report button
*Clear button
*Live scan output
*Authorized-testing warning

⚙️ Installation
Requirements
*Python 3.x
*Windows, Linux, or macOS
*Internet/network access for remote authorized targets
*Install Dependencies

Open a terminal in the project directory:
pip install requests
Tkinter is included with most standard Python installations. On some Linux distributions, it may need to be installed separately.

▶️ How to Run

Clone the repository:

git clone https://github.com/YOUR-USERNAME/AresVuln.git

Move into the project directory:

cd AresVuln

Run the scanner:

python aresvuln_scanner.py

Enter an authorized target URL and click:

START SCAN

📄 Exporting a Report

After the scan finishes:

1.Click EXPORT REPORT
2.Select a location
3.Enter a filename
4.Save the scan results as a .txt file

🧪 Recommended Testing Environment

For learning and demonstrations, use:

*Your own local web application
*A deliberately vulnerable local lab
*Systems where you have explicit authorization to perform security testing

📊 Project Architecture
                    ┌─────────────────────┐
                    │     AresVuln GUI     │
                    │       Tkinter        │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    Scan Controller   │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
        Port Scanner      HTTP Scanner     DNS Scanner
              │                │                │
              │        ┌───────┼────────┐       │
              │        │       │        │       │
              ▼        ▼       ▼        ▼       ▼
           TCP      Headers   SQLi   Reflection Subdomains
                                │
                                ▼
                       Additional Checks
                       ├── Sensitive Paths
                       ├── Directories
                       └── Open Redirect
                                │
                                ▼
                       ┌────────────────┐
                       │  Scan Results  │
                       └───────┬────────┘
                               │
                               ▼
                       ┌────────────────┐
                       │  TXT Report    │
                       └────────────────┘



                       
