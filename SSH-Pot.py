import paramiko
import socket
import threading
import json
import requests
import subprocess
import time
from datetime import datetime, timedelta

ABUSE_IPDB_API_KEY = 'Add API Key Here'
LOG_FILE = 'ssh_login_attempts.log'
HOST_KEY = paramiko.RSAKey.generate(2048)
PORTS = [2222, 2200, 22222, 50000, 3389, 1337, 10001, 222, 2022, 2181, 23, 2000, 830, 2002, 5353, 8081, 6000, 5900]
reported_ips = {}
reporting_interval = timedelta(minutes=15)
paramiko.util.log_to_file("/dev/null") 

def log_attempt(attempt):
    """Logs login attempt details to a file."""
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(json.dumps(attempt) + '\n')

def get_geolocation(ip):
    """Fetches geolocation information for a given IP address."""
    url = f'http://ip-api.com/json/{ip}'
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f'Error fetching geolocation data: {e}')
    return {}

def report_to_abuse_ipdb(ip):
    """Reports an IP address to AbuseIPDB API."""
    current_time = datetime.utcnow()
    if ip in reported_ips and (current_time - reported_ips[ip]) < reporting_interval:
        print(f'Skipping report for IP {ip} as it was reported recently.')
        return

    curl_command = [
        'curl', 'https://api.abuseipdb.com/api/v2/report',
        '--data-urlencode', f'ip={ip}',
        '-d', 'categories=18,22',
        '--data-urlencode', 'comment=[Birdo Server] SSH-Multi login Attempt',
        '-H', f'Key: {ABUSE_IPDB_API_KEY}',
        '-H', 'Accept: application/json'
    ]
    
    try:
        subprocess.run(curl_command, check=True)
        reported_ips[ip] = current_time
        print(f'Reported IP {ip} to AbuseIPDB successfully.')
    except subprocess.CalledProcessError as e:
        print(f'Failed to report IP {ip} to AbuseIPDB: {e}')

def ban_ip(ip, duration=30):
    """Bans an IP address for a specified duration (in minutes)."""
    ban_command = ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
    unban_command = ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']

    try:
        subprocess.run(ban_command, check=True)
        print(f'Banned IP {ip} successfully.')

        # Unban the IP after the specified duration
        time.sleep(duration * 60)
        subprocess.run(unban_command, check=True)
        print(f'Unbanned IP {ip} successfully.')
    except subprocess.CalledProcessError as e:
        print(f'Failed to ban/unban IP {ip}: {e}')

class FakeSSHServer(paramiko.ServerInterface):
    """Handles SSH server behavior for this honeypot."""
    def __init__(self, client_address):
        self.client_address = client_address
        self.username = ""
        self.password = ""
    
    def check_auth_password(self, username, password):
        """Authenticates using the provided username and password."""
        self.username = username
        self.password = password
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        """Handles channel requests (e.g., sessions)."""
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def get_allowed_auths(self, username):
        """Defines allowed authentication methods."""
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
    except paramiko.ssh_exception.SSHException as e:
        print(f"Exception (server): {e}")
        attempt = {
            'ip': addr[0],
            'error': f'SSH exception: {str(e)}',
            'timestamp': datetime.utcnow().isoformat()
        }
        log_attempt(attempt)
        report_to_abuse_ipdb(addr[0])
        threading.Thread(target=ban_ip, args=(addr[0],)).start()
    except ConnectionResetError as e:
        print(f"Socket exception: {e}")
        attempt = {
            'ip': addr[0],
            'error': 'Connection reset by peer',
            'timestamp': datetime.utcnow().isoformat()
        }
        log_attempt(attempt)
        report_to_abuse_ipdb(addr[0])
        threading.Thread(target=ban_ip, args=(addr[0],)).start()
    except (UnicodeDecodeError, EOFError, TimeoutError) as e:
        print(f"Protocol error: {e}")
        attempt = {
            'ip': addr[0],
            'error': f'SSH protocol error: {str(e)}',
            'timestamp': datetime.utcnow().isoformat()
        }
        log_attempt(attempt)
        report_to_abuse_ipdb(addr[0])
        threading.Thread(target=ban_ip, args=(addr[0],)).start()
    except Exception as e:
        # Catch any other unexpected exceptions
        print(f"Unexpected error: {e}")
        attempt = {
            'ip': addr[0],
            'error': f'Unexpected error: {str(e)}',
            'timestamp': datetime.utcnow().isoformat()
        }
        log_attempt(attempt)
        report_to_abuse_ipdb(addr[0])
        threading.Thread(target=ban_ip, args=(addr[0],)).start()
    finally:
        transport.close()


def start_server(port):
    """Starts the SSH honeypot server."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(100)
        print(f'Starting SSH server on port {port}')

        while True:
            client, addr = sock.accept()
            print(f'Connection from {addr}')
            threading.Thread(target=handle_connection, args=(client, addr)).start()
    except OSError as e:
        if e.errno == 98:
            print(f'Port {port} is already in use. Skipping...')
        else:
            print(f'Failed to start server on port {port}: {e}')

if __name__ == "__main__":
    threads = []
    for port in PORTS:
        thread = threading.Thread(target=start_server, args=(port,))
        thread.start()
        threads.append(thread)
    
    for thread in threads:
        thread.join()
