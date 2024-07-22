# SSH Honeypot

This repository contains three [3] variants of an SSH honeypot. The script is designed to capture login attempts for exact credentaisl used + reporting the IP addresses to AbuseIPDB. 

I am currently using this myself, [ AbuseipDB Results ](https://www.abuseipdb.com/user/137416) .

## Variants
 **SSH-Honeypot-All:**   This has both Geolocation and Logging.
 
 **SSH-Honeypot-NoGeo:**   This just collects the Username:Password used and the IP of the actor.
 
 **SSH-Honeypot-Clean:**   This only runs in the background to detect and report. 

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
4. You don’t need to manually remove any ports from the list; the script will simply skip any that are already in use.
    However, to run the server on the ports below 1024, you will need to have sudo / administrative privileges.
   ```python
    PORTS = [2222, 2200, 22222, 50000, 3389, 1337, 10001, 222, 2022, 2181, 23, 2000, 830, 2002, 5353, 8081, 6000, 5900]
    ```
   Im currently using these ports due to them being the most commonly used port for ssh on shodan / zoomeye.
   
## Usage

### 1. Just need to run the file

**Run:** `Python3 ssh-honeypot-All.py`

### 2. Running the logging varients will create the log file
**File:** `ssh_login_attempts.log`

   You can change the name of the log file to whatever.

  ### Example of the log file in action 
   
![Example](https://github.com/user-attachments/assets/000ff986-2d39-4748-9d48-07d4eeb26f69)


