import argparse
import re

def detect_sqli(log_entry):
    patterns = [
        # Classic SQL Injection (case-insensitive, encoded AND/OR)
        r"[^a-zA-Z0-9_.]+and\s+1=1|[^a-zA-Z0-9_.]+\%26\s+1=1",
        r"[^a-zA-Z0-9_.]+or\s+1=1|[^a-zA-Z0-9_.]+\%7C\s+1=1",
        # Union-based SQL Injection (case-insensitive, encoded union)
        r"union\s+select|%27UNION%27",
        # Error-based SQL Injection
        r"select\s+\*\s+from\s+.*\s+where\s+.*\s+=\s+convert\(\s+int\s*,\s*\(\s*select\s+.*\s*\)\s*\)",
        # Blind SQL Injection
        r"waitfor\s+delay\s+\'0:0:10\'",
        r"sleep\s*\(\s*[0-9]+\s*\)",
        # Time-based SQL Injection
        r"sleep\s*\(\s*[0-9]+\s*\)",
        # Single quote injection (plaintext, encoded, double-encoded)
        r"(\')|(\%27)|(\%2527)",
        # Comment injection
        r"(\-\-)|(\%2d\%2d)|(%23)",
        # Hash symbol injection
        r"#",
        # General SQL injection pattern (heuristic)
        r"/(\%3D|%3B|=|;)\s+[^n]*((%27)|(\'))\s*(\-\-)?/i",
        # Keyword patterns (union, select, etc.)
        r"(union|select|insert|update|delete|\bin|where)\s+.*?(--|\$|\%)",
        # Hex encoded characters
        r"0x[0-9a-f]+",
        # Double encoded characters
        r"%[0-9a-fA-F]{2}",
        # Inline comments
        r"--\s*",
        r"\/\*.*?\*\/",
        # Function-based SQL Injection
        r"exec\s*\(",
        r"execute\s*\(",
        r"sp_executesql",
    ]

    regex_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]

    for pattern in regex_patterns:
        if pattern.search(log_entry):
            return True
    return False

def analyze_iis_logs(file_path):
    try:
        with open(file_path, 'r') as file:
            for line_number, log_entry in enumerate(file, start=1):
                if detect_sqli(log_entry):
                    print(f"Potential SQL injection detected in IIS log at line {line_number}: {log_entry.strip()}")
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"Error opening file: {e}")

def analyze_apache_logs(file_path):
    try:
        with open(file_path, 'r') as file:
            for line_number, log_entry in enumerate(file, start=1):
                match = re.search(r'"(.*?)"', log_entry)
                if match:
                    request_line = match.group(1)
                    if detect_sqli(request_line):
                        print(f"Potential SQL injection detected in Apache log at line {line_number}: {log_entry.strip()}")
                
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"Error opening file: {e}")


def main():
    parser = argparse.ArgumentParser(description="Detect potential SQL injection in log files.")
    parser.add_argument("file_path", help="Path to the log file to analyze")
    parser.add_argument("--format", choices=["iis", "apache"], help="Specify the log format (IIS or Apache)")
    args = parser.parse_args()

    if args.format == "iis":
        analyze_iis_logs(args.file_path)
    elif args.format == "apache":
        analyze_apache_logs(args.file_path)
    else:
        print("Please specify the log format using the --format option (iis or apache).")

if __name__ == "__main__":
    main()
