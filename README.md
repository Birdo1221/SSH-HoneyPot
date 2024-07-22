# SSH Honeypot

This repository contains four variants of an SSH honeypot server script. The scripts are designed to capture login attempts, report malicious IP addresses to AbuseIPDB, and optionally log attempts and fetch geolocation data.

## Variants

1. **SSH Honeypot with Logging and Geolocation**: This script logs all SSH login attempts and fetches geolocation data for each IP address.
2. **SSH Honeypot with Logging Only**: This script logs all SSH login attempts but does not fetch geolocation data.
3. **SSH Honeypot with Geolocation Only**: This script fetches geolocation data for each IP address but does not log login attempts.
4. **SSH Honeypot without Logging or Geolocation**: This script is for the most simple setup.

## Getting Started

### Prerequisites

- Python 3.x
- Paramiko library
- Requests library
- Curl
- iptables

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

### 1. SSH Honeypot with Logging and Geolocation

**Run:** `Python3 ssh-honeypot-All.py`

