# ScanGuard | A reliable Python network port scanning tool 

ScanGuard is a Python-based network port scanning tool for enhanced cybersecurity and vulnerability assessment.

## What this does?

The script begins by importing the necessary modules, including socket for network communication, concurrent.futures for concurrent execution, queue for thread-safe data sharing, and threading for creating and managing threads. These modules provide the required functionalities for implementing a port scanner.

The validate_ports function is defined to validate a list of ports. It takes a list of ports as input and iterates over each port. Within the iteration, it removes any leading or trailing whitespace and checks if the port is a valid integer using the isdigit() method. If the port is a valid integer, it is further checked to ensure it falls within the valid range of 0 to 65535. The function returns a list of valid ports.

The port_scan function is defined to perform the actual scanning of a specific port on a target host. It takes a port number and a target host as input. Within the function, a TCP socket is created using socket.socket() with the address family set to IPv4 (socket.AF_INET) and the socket type set to TCP (socket.SOCK_STREAM). A timeout of 2 seconds is set on the socket using sock.settimeout(). The function then attempts to establish a connection with the target host on the specified port using sock.connect_ex(). If the result is 0, indicating a successful connection, the port number is returned. Otherwise, None is returned.

The worker function is defined as the worker thread function. It operates in an infinite loop and continuously retrieves ports from the shared queue. If a None value is received from the queue, indicating termination, the loop breaks, and the thread terminates. Otherwise, the port_scan function is called to check if the port is open on the target host. If an open port is found, it is appended to the results list. After processing a port, the task is marked as done using queue.task_done().

The scan_ports function serves as the main function that orchestrates the port scanning process. It takes a target host and a list of target ports as input. First, it resolves the IP address of the target host using socket.gethostbyname(). Then, it creates a ThreadPoolExecutor from the concurrent.futures module, which allows for concurrent execution of tasks using a pool of worker threads. The number of worker threads is specified by the num_threads variable.

Within the scan_ports function, a queue (port_queue) and a list (results) are created to store the open ports. Additionally, a list (threads) is initialized to keep track of the worker threads. To initiate the port scanning, the script creates num_threads worker threads by iterating over a range and creating instances of the threading.Thread class. Each worker thread is passed the worker function, the port_queue, the results list, and the target host as arguments. The threads are set as daemon threads using t.daemon = True, which allows the program to exit even if the worker threads are still running. The threads are then appended to the threads list.

After creating the worker threads, the script starts each thread by calling t.start(). The target ports are enqueued into the port_queue using port_queue.put(port). The script then waits for all tasks in the port_queue to be completed using port_queue.join(). This ensures that all ports have been processed by the worker threads. To stop the worker threads, None values are enqueued into the port_queue using port_queue.put(None). This signals the worker threads to break the loop and terminate. Finally, the script waits for all worker threads to finish using t.join(). The open ports in the results list are then displayed, or a message indicating no open ports are found is printed based on the results.

## Requirements
- Python 3
- Nmap installed on the system
- Understanding how to run a .py script

## Installation
``
git clone https://github.com/dragonGR/ScanGuard.git
``

``
cd ScanGuard
``

``
python3 port_scanner.py
``

## License
This project is licensed under the [MIT License](LICENSE).
