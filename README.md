# SSH Honeypot

This repository contains three [3] variants of an SSH honeypot. The script is designed to capture login attempts for exact credentaisl used + reporting the IP addresses to AbuseIPDB. 

I am currently using this myself, [ AbuseipDB Results ](https://www.abuseipdb.com/user/137416) .

## Variants

 **SSH-Honeypot-All with Logging and Geolocation** This has both Geolocation and Logging.
 **SSH-Honeypot-NoGeo just No Geolocation** This just collects the Username:Password used and the IP of the actor.
 **SSH-Honeypot-Clean without Logging or Geolocation** This only runs in the background to detect and report. 

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

### 2. Running the logging varients will create the log file
**File:** `ssh_login_attempts.log`

