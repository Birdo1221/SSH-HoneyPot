import socket
import threading
import requests
import subprocess
from datetime import datetime, timedelta
import time
import logging
import json
import os
from typing import Dict, Set
import ipaddress
import signal
import sys

class SMBHoneypot:
    def __init__(self, port: int = 445, ban_duration: int = 30):
        self.ABUSE_IPDB_API_KEY = 'Add API Key Here''
        self.SMB_PORT = port
        self.BAN_DURATION = ban_duration  # minutes
        self.reported_ips: Dict[str, datetime] = {}
        self.banned_ips: Set[str] = set()
        self.reporting_interval = timedelta(minutes=15)
        self.attempt_counts: Dict[str, int] = {}
        self.setup_logging()
        self.running = True
        self.whitelist = self.load_whitelist()
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.shutdown_handler)
        signal.signal(signal.SIGTERM, self.shutdown_handler)

    def setup_logging(self):
        """Configure logging with both file and console handlers"""
        # Ensure logs directory exists
        os.makedirs('logs', exist_ok=True)
        
        # Setup file logging with daily rotation
        log_file = f'logs/smb_attempts_{datetime.now().strftime("%Y%m%d")}.log'
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )

    def load_whitelist(self) -> Set[str]:
        """Load whitelisted IPs from config file"""
        try:
            with open('whitelist.json', 'r') as f:
                return set(json.load(f))
        except FileNotFoundError:
            with open('whitelist.json', 'w') as f:
                json.dump([], f)
            return set()

    def is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def report_to_abuse_ipdb(self, ip: str) -> None:
        """Report malicious IP to AbuseIPDB with enhanced error handling"""
        if not self.is_valid_ip(ip):
            logging.error(f"Invalid IP format: {ip}")
            return

        current_time = datetime.utcnow()
        if ip in self.reported_ips and (current_time - self.reported_ips[ip]) < self.reporting_interval:
            logging.info(f'Skipping report for IP {ip} - reported recently')
            return

        url = "https://api.abuseipdb.com/api/v2/report"
        headers = {
            "Key": self.ABUSE_IPDB_API_KEY,
            "Accept": "application/json"
        }
        
        try:
            response = requests.post(url, 
                data={
                    "ip": ip,
                    "categories": "18,14,15",
                    "comment": f"[Birdo Server] SMB Unauthorized Attempt (Attempts: {self.attempt_counts.get(ip, 1)})"
                },
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            self.reported_ips[ip] = current_time
            logging.info(f'Successfully reported IP {ip} to AbuseIPDB')
            
        except requests.exceptions.RequestException as e:
            logging.error(f'Failed to report IP {ip} to AbuseIPDB: {str(e)}')

    def ban_ip(self, ip: str) -> None:
        """Ban IP using iptables with improved error handling"""
        if ip in self.banned_ips or ip in self.whitelist:
            return

        try:
            # Add IP to banned set
            self.banned_ips.add(ip)
            
            # Ban command with rate limiting
            ban_command = f'iptables -A INPUT -s {ip} -p tcp --dport {self.SMB_PORT} -m state --state NEW -m recent --set'
            subprocess.run(ban_command, shell=True, check=True, capture_output=True)
            
            logging.info(f'Banned IP {ip}')
            
            # Schedule unban
            threading.Timer(self.BAN_DURATION * 60, self.unban_ip, args=[ip]).start()
            
        except subprocess.CalledProcessError as e:
            logging.error(f'Failed to ban IP {ip}: {e.stderr.decode()}')
            self.banned_ips.remove(ip)

    def unban_ip(self, ip: str) -> None:
        """Unban IP address"""
        try:
            unban_command = f'iptables -D INPUT -s {ip} -p tcp --dport {self.SMB_PORT} -m state --state NEW -m recent --remove'
            subprocess.run(unban_command, shell=True, check=True, capture_output=True)
            self.banned_ips.remove(ip)
            logging.info(f'Unbanned IP {ip}')
            
        except subprocess.CalledProcessError as e:
            logging.error(f'Failed to unban IP {ip}: {e.stderr.decode()}')

    def handle_connection(self, client: socket.socket, addr: tuple) -> None:
        """Handle incoming connection attempts"""
        ip_address = addr[0]
        
        if ip_address in self.whitelist:
            logging.info(f'Whitelisted IP attempted connection: {ip_address}')
            client.close()
            return

        # Increment attempt counter
        self.attempt_counts[ip_address] = self.attempt_counts.get(ip_address, 0) + 1
        
        logging.warning(f'Unauthorized connection attempt from {ip_address} (Attempt #{self.attempt_counts[ip_address]})')
        
        try:
            # Try to read any credentials sent
            client.settimeout(5)
            data = client.recv(1024)
            if data:
                # Log potential credentials/payload (safely handle encoding issues)
                try:
                    decoded_data = data.decode('utf-8', errors='replace')
                    logging.info(f'Received data from {ip_address}: {decoded_data[:200]}')
                except Exception as e:
                    logging.error(f'Failed to decode data from {ip_address}: {str(e)}')
                    
        except socket.timeout:
            logging.debug(f'No data received from {ip_address}')
        except Exception as e:
            logging.error(f'Error handling connection from {ip_address}: {str(e)}')
        finally:
            client.close()
            
        # Report and ban if multiple attempts
        if self.attempt_counts[ip_address] >= 3:
            self.report_to_abuse_ipdb(ip_address)
            self.ban_ip(ip_address)

    def start_server(self) -> None:
        """Start the SMB honeypot server"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', self.SMB_PORT))
            sock.listen(100)
            sock.settimeout(1)  # Allow for clean shutdown
            
            logging.info(f'SMB Honeypot started on port {self.SMB_PORT}')
            
            while self.running:
                try:
                    client, addr = sock.accept()
                    threading.Thread(target=self.handle_connection, args=(client, addr)).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    logging.error(f'Error accepting connection: {str(e)}')
                    
        except OSError as e:
            if e.errno == 98:
                logging.error(f'Port {self.SMB_PORT} is already in use')
            else:
                logging.error(f'Failed to start server: {str(e)}')
        finally:
            sock.close()

    def shutdown_handler(self, signum, frame):
        """Handle graceful shutdown"""
        logging.info('Shutting down SMB Honeypot...')
        self.running = False
        
        # Unban all IPs
        for ip in list(self.banned_ips):
            self.unban_ip(ip)

if __name__ == "__main__":
    honeypot = SMBHoneypot()
    honeypot.start_server()
