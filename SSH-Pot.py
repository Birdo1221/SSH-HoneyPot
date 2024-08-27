import paramiko
import socket
import threading
import json
import requests
import subprocess
from datetime import datetime, timedelta
import time
from concurrent.futures import ThreadPoolExecutor

ABUSE_IPDB_API_KEY = 'e99245c63620b31a4336b6eb26d0d071021a7b997412918a601e0d17b9975f562671d9bbada9f7b1'
LOG_FILE = 'ssh_login_attempts.log'
HOST_KEY = paramiko.RSAKey.generate(2048)
PORTS = [2222, 2200, 22222, 50000, 3389, 1337, 10001, 222, 2022, 2181, 23, 2000, 830, 2002, 5353, 8081, 6000, 5900]

reported_ips = {}
reporting_interval = timedelta(minutes=15)

def log_attempt(attempt):
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(json.dumps(attempt) + '\n')
    print(f"Logged attempt: {attempt}")

def get_geolocation(ip):
    url = f'http://ip-api.com/json/{ip}'
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
    except requests.RequestException as e:
        print(f'Error fetching geolocation data: {e}')
    return {}

def report_to_abuse_ipdb(ip):
    current_time = datetime.utcnow()
    if ip in reported_ips and (current_time - reported_ips[ip]) < reporting_interval:
        print(f'Skipping report for IP {ip} as it was reported recently.')
        return
    
    url = "https://api.abuseipdb.com/api/v2/report"
    data = {
        "ip": ip,
        "categories": "18,22,14",
        "comment": "[Birdo Server] SSH-Multi login Attempt"
    }
    headers = {
        "Key": ABUSE_IPDB_API_KEY,
        "Accept": "application/json"
    }

    try:
        response = requests.post(url, data=data, headers=headers, timeout=10)
        if response.status_code == 200:
            reported_ips[ip] = current_time
            print(f'Reported IP {ip} to AbuseIPDB successfully.')
        else:
            print(f'Failed to report IP {ip} to AbuseIPDB: {response.status_code} {response.text}')
    except requests.RequestException as e:
        print(f'Error reporting IP {ip} to AbuseIPDB: {e}')

def ban_ip(ip):
    ban_command = f'iptables -A INPUT -s {ip} -j DROP'
    unban_command = f'iptables -D INPUT -s {ip} -j DROP'

    try:
        subprocess.run(ban_command, shell=True, check=True)
        print(f'Banned IP {ip} successfully.')

        # Unban the IP after 30 minutes
        time.sleep(30 * 60)
        subprocess.run(unban_command, shell=True, check=True)
        print(f'Unbanned IP {ip} successfully.')
    except subprocess.CalledProcessError as e:
        print(f'Failed to ban/unban IP {ip}: {e}')

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_address):
        self.client_address = client_address
        self.username = ""
        self.password = ""
    
    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def get_allowed_auths(self, username):
        return 'password'

def handle_connection(client, addr):
    transport = paramiko.Transport(client)
    transport.add_server_key(HOST_KEY)
    server = FakeSSHServer(addr)
    
    try:
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel is not None:
            channel.send("Login attempt recorded. Thank you.\n")
            channel.close()
    except (paramiko.SSHException, UnicodeDecodeError, EOFError, TimeoutError) as e:
        attempt = {
            'ip': addr[0],
            'error': f'SSH protocol error: {str(e)}',
            'timestamp': datetime.utcnow().isoformat()
        }
        log_attempt(attempt)
        report_to_abuse_ipdb(addr[0])
        threading.Thread(target=ban_ip, args=(addr[0],)).start()
    finally:
        transport.close()

    attempt = {
        'ip': addr[0],
        'username': server.username,
        'password': server.password,
        'geolocation': get_geolocation(addr[0]),
        'timestamp': datetime.utcnow().isoformat()
    }

    log_attempt(attempt)
    report_to_abuse_ipdb(addr[0])
    threading.Thread(target=ban_ip, args=(addr[0],)).start()

def start_server(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(100)
        print(f'Starting SSH server on port {port}')

        with ThreadPoolExecutor(max_workers=10) as executor:
            while True:
                client, addr = sock.accept()
                print(f'Connection from {addr}')
                executor.submit(handle_connection, client, addr)
    except OSError as e:
        if e.errno == 98:
            print(f'Port {port} is already in use. Skipping...')
        else:
            print(f'Failed to start server on port {port}: {e}')
    except Exception as e:
        print(f'Unexpected error: {e}')
    finally:
        sock.close()

if __name__ == "__main__":
    threads = []
    for port in PORTS:
        thread = threading.Thread(target=start_server, args=(port,))
        thread.start()
        threads.append(thread)
    
    for thread in threads:
        thread.join()
