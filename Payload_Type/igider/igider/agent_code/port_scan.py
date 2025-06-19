import socket
import json
import base64
from concurrent.futures import ThreadPoolExecutor
import time

class PortScan:
    def __init__(self, current_directory):
        self.current_directory = current_directory
        self.taskings = []

    def scan_port(self, ip, port, timeout=1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            banner = ""
            if result == 0:
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()[:100]
                except:
                    pass
            sock.close()
            return port, result == 0, banner
        except:
            return port, False, ""

    def port_scan(self, task_id, ip_range, port_range, timeout=1, max_threads=100):
        start_time = time.time()
        results = []
        ip_list = []
        port_list = []

        # Parse IP range (e.g., 192.168.1.1-192.168.1.10)
        ip_start, ip_end = ip_range.split('-')
        ip_start_parts = ip_start.split('.')
        ip_end_parts = ip_end.split('.') if ip_end else ip_start_parts
        start_last_octet = int(ip_start_parts[-1])
        end_last_octet = int(ip_end_parts[-1]) if ip_end else start_last_octet
        base_ip = '.'.join(ip_start_parts[:-1])
        ip_list = [f"{base_ip}.{i}" for i in range(start_last_octet, end_last_octet + 1)]

        # Parse port range (e.g., 80-100)
        port_start, port_end = map(int, port_range.split('-'))
        port_list = list(range(port_start, port_end + 1))

        def scan_ip(ip):
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = [executor.submit(self.scan_port, ip, port, timeout) for port in port_list]
                for future in futures:
                    port, is_open, banner = future.result()
                    if is_open:
                        results.append({"ip": ip, "port": port, "banner": banner})

        for ip in ip_list:
            if [task for task in self.taskings if task["task_id"] == task_id][0]["stopped"]:
                return json.dumps({"status": "stopped", "results": results})
            scan_ip(ip)

        return json.dumps({
            "status": "completed",
            "results": results,
            "elapsed_time": time.time() - start_time
        })