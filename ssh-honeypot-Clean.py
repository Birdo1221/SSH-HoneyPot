import paramiko
import socket
import threading
import requests
import subprocess
from datetime import datetime, timedelta
import time

ABUSE_IPDB_API_KEY = 'Replace with Abuse-IPDB API Token'
HOST_KEY = paramiko.RSAKey.generate(2048)
PORTS = [2222, 2200, 22222, 50000, 3389, 1337, 10001, 222, 2022, 2181, 23, 2000, 830, 2002, 5353, 8081, 6000, 5900]

reported_ips = {}
reporting_interval = timedelta(minutes=15)

def report_to_abuse_ipdb(ip):
    current_time = datetime.utcnow()
    if ip in reported_ips and (current_time - reported_ips[ip]) < reporting_interval:
        print(f'Skipping report for IP {ip} as it was reported recently.')
        return
    
    curl_command = f'curl https://api.abuseipdb.com/api/v2/report \
        --data-urlencode "ip={ip}" \
        -d categories=18,22 \
        --data-urlencode "comment= [Birdo Server] SSH-Multi login Attempt" \
        -H "Key: {ABUSE_IPDB_API_KEY}" \
        -H "Accept: application/json"'
    
    try:
        subprocess.run(curl_command, shell=True, check=True)
        reported_ips[ip] = current_time
        print(f'Reported IP {ip} to AbuseIPDB successfully.')
    except subprocess.CalledProcessError as e:
        print(f'Failed to report IP {ip} to AbuseIPDB: {e}')

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
    except (paramiko.SSHException, UnicodeDecodeError, EOFError, TimeoutError):
        report_to_abuse_ipdb(addr[0])
        threading.Thread(target=ban_ip, args=(addr[0],)).start()
        transport.close()
        return

    report_to_abuse_ipdb(addr[0])
    threading.Thread(target=ban_ip, args=(addr[0],)).start()
    transport.close()

def start_server(port):
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
