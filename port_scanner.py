import logging
import concurrent.futures
import socket
import re
import argparse
import signal
import sys

# ANSI escape codes for text formatting
BOLD_WHITE = '\033[1;97m'
GREEN = '\033[1;32m'
RED = '\033[1;31m'
BLACK = '\033[1;30m'
RESET = '\033[0m'

class CustomFormatter(logging.Formatter):
    def format(self, record):
        # Set color based on log level
        level_color = GREEN if record.levelname == "INFO" else RED

        # Format the log message with colored level and separators
        log_fmt = (f"{BOLD_WHITE}[%(asctime)s]{RESET} {BLACK}-{RESET} "
                   f"{level_color}%(levelname)s{RESET} {BLACK}-{RESET} %(message)s")
        formatter = logging.Formatter(log_fmt, datefmt='%Y-%m-%d %H:%M:%S')
        return formatter.format(record)

def port_scan(port, target_host, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_host, int(port)))
            if result == 0:
                return port
    except socket.error as e:
        logging.debug(f"Socket error for port {port}: {e}")
    return None

def scan_ports(target_host, target_ports, num_threads=10, timeout=2):
    try:
        target_ip = socket.gethostbyname(target_host)
        logging.info(f"Resolved IP: {target_ip}")
    except socket.gaierror as e:
        logging.error(f"Unable to resolve target host: {e}")
        return

    results = set()  # Use a set to avoid duplicate entries

    def worker(port):
        result = port_scan(port, target_ip, timeout)
        if result is not None:
            results.add(result)

    logging.info(f"Starting scan on target: {target_host} ({target_ip})")

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker, port) for port in target_ports]

            # Wait for all futures to complete
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logging.debug(f"Error during scan: {e}")
    except KeyboardInterrupt:
        logging.info("Exiting...")
        sys.exit(0)

    # Display results
    open_ports = sorted(results)
    if open_ports:
        logging.info("Open ports found:")
        for port in open_ports:
            print(f"{GREEN}Port {port} is open{RESET}")
    else:
        logging.info("No open ports found.")

def handle_exit(signal, frame):
    logging.info("Exiting...")
    sys.exit(0)

def main():
    # Set up signal handler for clean exit
    signal.signal(signal.SIGINT, handle_exit)

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
