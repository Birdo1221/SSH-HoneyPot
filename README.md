# SSH Honeypot

This repository contains four variants of an SSH honeypot server script. The scripts are designed to capture login attempts, report malicious IP addresses to AbuseIPDB, and optionally log attempts and fetch geolocation data.
This Logs The Exact Credentials They Used.

## Variants

 **SSH Honeypot with Logging and Geolocation**
 **SSH Honeypot with Logging Only**
 **SSH Honeypot with Geolocation Only**
 **SSH Honeypot without Logging or Geolocation**: 

## Getting Started

### Prerequisites
- Python 3.x
- Paramiko library
- Requests library
- Curl
- iptables  ==> Linux Only, Will need to find a Windows Alternative

### Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/ssh-honeypot.git
    cd ssh-honeypot
    ```

2. Install the required Python packages:
    ```sh
    pip install paramiko requests
    ```

3. Replace the placeholder in the script with your Abuse-IPDB API key:
    ```python
    ABUSE_IPDB_API_KEY = 'Replace with Abuse-IPDB API Token'
    ```
## Usage

### 1. Just need to run the file

**Run:** `Python3 ssh-honeypot-All.py`

