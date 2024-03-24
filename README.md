# SQL Injection Watchdog 
A Python Script for IIS Log Analysis (Currently Supports IIS Servers)
This is a CLI(command line interface) based tool. The script watchdog.py, helps identify potential SQL injection attempts within an IIS server log file. It scans for various patterns commonly used in SQL injection attacks targeting web applications running on IIS servers.

## Disclaimer:
This script is for educational purposes only and should not be considered a complete security solution.
This script is currently designed to analyze IIS server log files. The format of Apache server logs differs, and this script might not be directly compatible without modifications.

## Features:
- Analyzes IIS server log files.
- Identifies potential SQL injection patterns.
- Reports line numbers and log entries with potential threats.

## Reqirements:
Python 3.x

## Usage:
1. Clone the repository:
   sh
   git clone https://github.com/flamin-goes/SQLiWatchdog.git
   
2. Run the script:
   Open your terminal and navigate to the directory where you saved the script.
   Use the following command, replacing path/to/your/log_file.log with the actual path to your IIS server log file:
   sh
   python SQLiWatchdog.py path/to/your/log_file.log

## Output:
The script scans the log file and reports any lines containing potential SQL injection patterns. The output will look something like:
sh
Potential SQL injection detected at line 123: GET /login.php?id=1+AND+1=1 HTTP/1.1

## Shortcomings:
- Limited Scope:
  The script focuses on common SQL injection patterns. New attack techniques might emerge requiring updates to the detection patterns.
- False Positives:
  Some patterns might trigger alerts on legitimate user input. Manual verification is recommended.
- Basic Logging:
  The script currently prints findings to the console. Future improvements could involve logging to a file or integrating with security tools.

## Scope:
- Update detection patterns for emerging threats.
- Implement methods to reduce false positives.
- Explore support for Apache server logs.
