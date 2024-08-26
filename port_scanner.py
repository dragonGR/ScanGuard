import logging
import concurrent.futures
import socket
import re
import argparse

# ANSI escape codes for text formatting
BOLD_WHITE = '\033[1;97m'
GREEN = '\033[1;32m'
BLACK = '\033[1;30m'
RESET = '\033[0m'

class CustomFormatter(logging.Formatter):
    def format(self, record):
        # Set color based on log level
        level_color = GREEN if record.levelname == "INFO" else RESET
        
        # Format the log message with colored level and separators
        log_fmt = f"{BOLD_WHITE}[%(asctime)s]{RESET} {BLACK}-{RESET} {level_color}%(levelname)s{RESET} {BLACK}-{RESET} %(message)s"
        formatter = logging.Formatter(log_fmt, datefmt='%Y-%m-%d %H:%M:%S')
        return formatter.format(record)

def port_scan(port, target_host, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_host, int(port)))
            if result == 0:
                return port
    except socket.error:
        return None

def scan_ports(target_host, target_ports, num_threads=10, timeout=2):
    # Ensure target_host is in proper format
    if not re.match(r"^(http://|https://)", target_host):
        target_host = "http://" + target_host if any(char.isdigit() for char in target_host) else "https://" + target_host

    logging.info(f"Scanning target: {target_host}")

    results = set()  # Use a set for unique results

    def worker(port):
        result = port_scan(port, target_host, timeout)
        if result is not None:
            results.add(result)

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, port) for port in target_ports]

        # Wait for all futures to complete
        concurrent.futures.wait(futures)

    # Display results
    open_ports = sorted(results)
    if open_ports:
        for port in open_ports:
            print(f"Port {port} is open")
    else:
        print("No open ports found based on the provided input.")

def main():
    parser = argparse.ArgumentParser(description='Scan ports on a target host.')
    parser.add_argument('target_host', type=str, help='The target host to scan.')
    parser.add_argument('--ports', type=str, default='1-65535', help='Range of ports to scan (default: 1-65535).')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads to use (default: 10).')
    parser.add_argument('--timeout', type=int, default=2, help='Socket timeout in seconds (default: 2).')
    parser.add_argument('--log-level', type=str, default='INFO', help='Logging level (default: INFO).')

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO), format='%(message)s')
    logger = logging.getLogger()
    logger.handlers[0].setFormatter(CustomFormatter())

    # Parse ports
    try:
        port_range = args.ports.split('-')
        if len(port_range) == 2:
            target_ports = list(range(int(port_range[0]), int(port_range[1]) + 1))
        else:
            raise ValueError("Invalid port range format. Use 'start-end'.")
    except ValueError as e:
        logging.error(f"Port range error: {e}")
        return

    # Start port scanning
    scan_ports(args.target_host, target_ports, num_threads=args.threads, timeout=args.timeout)

if __name__ == "__main__":
    main()
