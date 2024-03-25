# SQL Injection Watchdog 
A Python Script for Log Analysis (Compatible with IIS and Apache Servers)
This is a CLI (command-line interface) based tool designed to identify potential SQL injection attempts within web server log files. The script `watchdog.py` scans log files for various patterns commonly used in SQL injection attacks targeting web applications running on both IIS and Apache servers.

## Disclaimer:
This script is for educational purposes only and should not be considered a complete security solution.

## Features:
- Analyzes both Apache and IIS server log files.
- Identifies potential SQL injection patterns.
- Reports line numbers and log entries with potential threats.
- Compatible with linux OS.

## Reqirements:
Python 3.x

## Usage:
1. **Clone the repository:**
   ```
   git clone https://github.com/flamin-goes/SQLiWatchdog.git
   ```
   
2. **Run the script:**
   Open your terminal and navigate to the directory where you saved the script.
   Use the following command, replacing `path/to/your/log_file.log` with the actual path to your server log file:
   ```
   python SQLiWatchdog.py --format [iis/apache] path/to/your/log_file.log
   ```
   
## Output:
The script scans the log file and reports any lines containing potential SQL injection patterns. The output will look something like:
```
Potential SQL injection detected at line 123: GET /login.php?id=1+AND+1=1 HTTP/1.1
```
`ITS A CLI BASED TOOL SO YOU CAN MOST DEFINITELY STORE THE OUTPUT/RESULTS OF THE LOG SCAN IN ANY TEXT FILE YOU WANT.`

## Shortcomings:
- *Limited Scope*:
  The script focuses on common SQL injection patterns. New attack techniques might emerge requiring updates to the detection patterns.
- *False Positives*:
  Some patterns might trigger alerts on legitimate user input. Manual verification is recommended.
- *Basic Logging*:
  The script currently prints findings to the console. Future improvements could involve logging to a file or integrating with security tools.

## Scope:
- Update detection patterns for emerging threats.
- Implement methods to reduce false positives.
- Explore support for Apache server logs.
