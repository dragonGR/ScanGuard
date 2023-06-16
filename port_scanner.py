import nmap
import concurrent.futures
import queue
import threading
import socket
import re


def port_scan(port, target_host):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            result = sock.connect_ex((target_host, int(port)))
            if result == 0:
                return port
    except socket.error:
        return None


def worker(queue, results, target_host):
    while True:
        port = queue.get()
        if port is None:
            break
        result = port_scan(port, target_host)
        if result is not None:
            results.append(result)
        queue.task_done()


def scan_ports(target_host, target_ports, num_threads=10):
    try:
        if any(char.isdigit() for char in target_host):
            if not re.match(r"^http://", target_host):
                target_host = "http://" + target_host
        else:
            if not re.match(r"^https://", target_host):
                target_host = "https://" + target_host

        print(f"Scanning target: {target_host}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            port_queue = queue.Queue()
            results = []
            threads = []

            # Create worker threads
            for _ in range(num_threads):
                t = threading.Thread(target=worker, args=(port_queue, results, target_host))
                t.daemon = True
                threads.append(t)

            # Start worker threads
            for t in threads:
                t.start()

            # Enqueue target ports
            for port in target_ports:
                port_queue.put(port)

            # Wait for all tasks to complete
            port_queue.join()

            # Stop worker threads
            for _ in range(num_threads):
                port_queue.put(None)
            for t in threads:
                t.join()

            # Display results
            open_ports = sorted(results)
            if open_ports:
                for port in open_ports:
                    print(f"Port {port} is open")
            else:
                print("No open ports found based on the provided input.")

    except nmap.PortScannerError:
        print("Error occurred while scanning")
    except KeyboardInterrupt:
        print("Port scanning interrupted")


if __name__ == "__main__":
    target_host = input("Enter the target host: ")

    if target_host:
        num_threads = 10  # Adjust the number of threads based on system capabilities
        nm = nmap.PortScanner()
        target_ports = list(range(1, 65536))  # Scan all ports from 1 to 65535
        scan_ports(target_host, target_ports)
    else:
        print("Invalid input. Please provide a valid target host.")
