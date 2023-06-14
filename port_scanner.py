import socket
import concurrent.futures
import queue
import threading

def validate_ports(ports):
    valid_ports = []
    for port in ports:
        port = port.strip()
        if port.isdigit():
            port = int(port)
            if 0 <= port <= 65535:
                valid_ports.append(port)
    return valid_ports

def port_scan(port, target_host):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            result = sock.connect_ex((target_host, port))
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

def scan_ports(target_host, target_ports):
    try:
        ip = socket.gethostbyname(target_host)
        print(f"Scanning target: {target_host} ({ip})")

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

    except socket.gaierror:
        print("Invalid hostname")
    except KeyboardInterrupt:
        print("Port scanning interrupted")

target_host = input("Enter the target host: ")
target_ports = input("Enter the target ports (comma-separated): ").split(",")
target_ports = validate_ports(target_ports)

if target_host and target_ports:
    num_threads = 10  # Adjust the number of threads based on system capabilities
    scan_ports(target_host, target_ports)
else:
    print("Invalid input. Please provide a valid target host and ports.")
