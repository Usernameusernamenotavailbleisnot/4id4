import requests
import json
import time
import os
import sys
from datetime import datetime
from web3 import Web3
from eth_account.messages import encode_defunct
from loguru import logger
import glob
import random
from requests.exceptions import ProxyError, ConnectTimeout, SSLError, ConnectionError

# Configuration
BASE_URL = "https://back.aidapp.com"
CAMPAIGN_ID = "6b963d81-a8e9-4046-b14f-8454bc3e6eb2"
SLEEP_BETWEEN_REQUESTS = 2  # seconds
MAX_RETRIES = 3  # Maximum number of retries for failed requests
RETRY_DELAY = 3  # Base delay between retries (in seconds)

# Configure Loguru logger
logger.remove()
logger.add(
    sys.stdout,
    format="<green>{time:MM/DD/YYYY - HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{message}</cyan>",
    level="INFO",
    colorize=True
)
logger.add(
    "aida.log",
    format="{time:MM/DD/YYYY - HH:mm:ss} | {level: <8} | {message}",
    level="DEBUG",
    rotation="5 MB"
)

# Headers setup
headers = {
    "accept": "*/*",
    "accept-encoding": "gzip, deflate, br",
    "accept-language": "en-US,en;q=0.8",
    "origin": "https://my.aidapp.com",
    "referer": "https://my.aidapp.com/",
    "sec-ch-ua": "\"Not(A:Brand\";v=\"99\", \"Chrome\";v=\"133\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-site",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
}

# Mission types that can be completed automatically
SUPPORTED_MISSION_TYPES = [
    "MANUAL", 
    "CONNECT_TWITTER", 
    "CONNECT_WALLET",
    "LIKE_TWEET", 
    "JOIN_TELEGRAM",
    "CREATE_WALLET"
]

# Function to make HTTP requests with retries and error handling
def make_request(method, url, wallet_index, proxy=None, retries=MAX_RETRIES, **kwargs):
    """Make HTTP request with retries and error handling for proxies"""
    proxies = None
    if proxy:
        proxies = {
            "http": proxy,
            "https": proxy
        }
    
    retry_count = 0
    last_exception = None
    
    while retry_count < retries:
        try:
            # Add proxies to the request if provided
            if proxies:
                kwargs['proxies'] = proxies
            
            # Set timeout for the request
            if 'timeout' not in kwargs:
                kwargs['timeout'] = 30
            
            # Make the request based on the method
            if method.upper() == 'GET':
                response = requests.get(url, **kwargs)
            elif method.upper() == 'POST':
                response = requests.post(url, **kwargs)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            # Check if the request was successful
            if response.status_code < 400:
                return response
            
            # Handle specific HTTP status codes
            if response.status_code == 403:
                logger.warning(f"Wallet {wallet_index} | Access forbidden (403). Proxy might be banned or IP restricted.")
            elif response.status_code == 429:
                logger.warning(f"Wallet {wallet_index} | Rate limited (429). Waiting longer before retry.")
                # Wait longer for rate limiting
                time.sleep(RETRY_DELAY * (retry_count + 2))
            else:
                logger.warning(f"Wallet {wallet_index} | HTTP error: {response.status_code} - {response.text}")
            
            # HTTP error but not a proxy/connection issue, may still retry
            last_exception = Exception(f"HTTP {response.status_code}: {response.text[:100]}...")
            
        except ProxyError as e:
            logger.error(f"Wallet {wallet_index} | Proxy error: {str(e)}")
            last_exception = e
        except ConnectTimeout as e:
            logger.error(f"Wallet {wallet_index} | Connection timeout: {str(e)}")
            last_exception = e
        except ConnectionError as e:
            logger.error(f"Wallet {wallet_index} | Connection error: {str(e)}")
            last_exception = e
        except SSLError as e:
            logger.error(f"Wallet {wallet_index} | SSL error: {str(e)}")
            last_exception = e
        except requests.exceptions.RequestException as e:
            logger.error(f"Wallet {wallet_index} | Request error: {str(e)}")
            last_exception = e
        except Exception as e:
            logger.error(f"Wallet {wallet_index} | Unexpected error: {str(e)}")
            last_exception = e
        
        # Increase retry count and wait before retrying
        retry_count += 1
        
        # If this was the last retry, report failure
        if retry_count >= retries:
            logger.error(f"Wallet {wallet_index} | Failed after {retries} retries")
            break
        
        # Use exponential backoff with jitter for retries
        backoff_time = RETRY_DELAY * (2 ** retry_count) + random.uniform(0, 1)
        logger.info(f"Wallet {wallet_index} | Retrying in {backoff_time:.2f} seconds... (Attempt {retry_count+1}/{retries})")
        time.sleep(backoff_time)
    
    # If all retries failed, raise the last exception
    raise last_exception or Exception("Request failed after all retries")

# Get proxies from proxy.txt
def get_proxies():
    """Get all proxies from proxy.txt"""
    proxies = []
    
    if os.path.exists("proxy.txt"):
        try:
            with open("proxy.txt", "r") as file:
                for line in file:
                    proxy = line.strip()
                    if proxy:
                        if not proxy.startswith("http"):
                            # Format proxy properly
                            proxy = f"http://{proxy}"
                        proxies.append(proxy)
            logger.success(f"Successfully loaded {len(proxies)} proxies from proxy.txt")
        except Exception as e:
            logger.error(f"Error reading proxy.txt: {str(e)}")
    
    if not proxies:
        logger.warning("No proxies found in proxy.txt. Will run without proxies.")
    
    return proxies

# Verify proxy functionality
def verify_proxy(proxy, wallet_index):
    """Test if a proxy is working by making a simple request"""
    try:
        logger.info(f"Wallet {wallet_index} | Testing proxy: {proxy}")
        
        # Use a proxy testing service or a simple request to verify
        test_url = "https://api.ipify.org?format=json"
        proxies = {
            "http": proxy,
            "https": proxy
        }
        
        response = requests.get(test_url, proxies=proxies, timeout=10)
        
        if response.status_code == 200:
            ip_data = response.json()
            logger.success(f"Wallet {wallet_index} | Proxy working! IP: {ip_data.get('ip', 'unknown')}")
            return True
        else:
            logger.warning(f"Wallet {wallet_index} | Proxy test failed with status code: {response.status_code}")
            return False
    
    except Exception as e:
        logger.error(f"Wallet {wallet_index} | Proxy verification error: {str(e)}")
        return False

# Authentication functions
def get_private_keys():
    """Get all private keys from pk.txt or all pk_*.txt files"""
    private_keys = []
    
    # Check for pk.txt first
    if os.path.exists("pk.txt"):
        try:
            with open("pk.txt", "r") as file:
                for line in file:
                    pk = line.strip()
                    if pk:
                        # Remove '0x' prefix if present
                        if pk.startswith('0x'):
                            pk = pk[2:]
                        private_keys.append(pk)
        except Exception as e:
            logger.error(f"Error reading pk.txt: {str(e)}")
    
    # Check for pk_*.txt files
    pk_files = glob.glob("pk_*.txt")
    for pk_file in pk_files:
        try:
            with open(pk_file, "r") as file:
                pk = file.read().strip()
                if pk:
                    # Remove '0x' prefix if present
                    if pk.startswith('0x'):
                        pk = pk[2:]
                    private_keys.append(pk)
        except Exception as e:
            logger.error(f"Error reading {pk_file}: {str(e)}")
    
    if not private_keys:
        logger.error("No private keys found. Please create a file named pk.txt with your private keys")
        sys.exit(1)
    
    return private_keys

def authenticate(private_key, wallet_index, proxy=None):
    """Authenticate with the AIDA platform using the wallet's private key"""
    w3 = Web3()
    
    if not private_key.startswith('0x'):
        private_key = '0x' + private_key
    
    account = w3.eth.account.from_key(private_key)
    wallet_address = account.address
    logger.info(f"Wallet {wallet_index} | Using address: {wallet_address}")
    
    if proxy:
        logger.info(f"Wallet {wallet_index} | Using proxy: {proxy}")
    
    timestamp = int(time.time() * 1000)
    message = f"MESSAGE_ETHEREUM_{timestamp}:{timestamp}"
    
    message_to_sign = encode_defunct(text=message)
    signed_message = account.sign_message(message_to_sign)
    signature = signed_message.signature.hex()
    
    # Ensure signature has 0x prefix
    if not signature.startswith('0x'):
        signature = '0x' + signature
    
    logger.debug(f"Wallet {wallet_index} | Generated message: {message}")
    logger.debug(f"Wallet {wallet_index} | Generated signature: {signature}")
    
    # Using token parameter (original format)
    login_params = {
        "strategy": "WALLET",
        "chainType": "EVM",
        "address": wallet_address,
        "token": message,
        "signature": signature,
        "inviter":"ZF2_cLsZuRf5q5X"
    }
    
    login_url = f"{BASE_URL}/user-auth/login"
    
    try:
        response = make_request('GET', login_url, wallet_index, proxy=proxy, params=login_params, headers=headers)
        
        logger.success(f"Wallet {wallet_index} | Authentication successful!")
        auth_data = response.json()
        access_token = auth_data["tokens"]["access_token"]
        auth_headers = headers.copy()
        auth_headers["Authorization"] = f"Bearer {access_token}"
        return auth_headers, auth_data["user"]["evmAddress"]
    
    except Exception as e:
        logger.error(f"Wallet {wallet_index} | Authentication failed: {str(e)}")
        return None, None

# Campaign functions
def join_campaign(auth_headers, wallet_index, proxy=None):
    """Join the AIDA campaign"""
    join_url = f"{BASE_URL}/questing/campaign/{CAMPAIGN_ID}/join"
    
    try:
        response = make_request('POST', join_url, wallet_index, proxy=proxy, headers=auth_headers)
        
        # 201 is success for a creation operation
        if response.status_code == 201 or response.status_code == 200:
            logger.success(f"Wallet {wallet_index} | Successfully joined campaign")
            return True
        elif response.status_code == 409:
            logger.info(f"Wallet {wallet_index} | Already joined campaign")
            return True
        else:
            logger.error(f"Wallet {wallet_index} | Failed to join campaign: {response.status_code} - {response.text}")
            return False
    
    except Exception as e:
        logger.error(f"Wallet {wallet_index} | Error joining campaign: {str(e)}")
        return False
    
    finally:
        time.sleep(SLEEP_BETWEEN_REQUESTS)

def get_campaign_status(auth_headers, wallet_index, proxy=None):
    """Get the current status of the campaign for the authenticated wallet"""
    url = f"{BASE_URL}/questing/campaign?filter[id]={CAMPAIGN_ID}"
    
    try:
        response = make_request('GET', url, wallet_index, proxy=proxy, headers=auth_headers)
        
        try:
            data = response.json()
            if data.get("count", 0) > 0 and len(data.get("data", [])) > 0:
                campaign_data = data["data"][0]
                
                # Debug output
                logger.debug(f"Wallet {wallet_index} | Campaign Data Structure:")
                logger.debug(json.dumps(campaign_data, indent=2))
                
                is_joined = campaign_data.get("joined", False)
                completed_missions = campaign_data.get("completedMissionsCount", 0)
                total_missions = campaign_data.get("missionsCount", 0)
                balance = campaign_data.get("balance", 0)
                
                return {
                    "joined": is_joined,
                    "completed_missions": completed_missions,
                    "total_missions": total_missions,
                    "balance": balance
                }
            else:
                logger.warning(f"Wallet {wallet_index} | No campaign data found in response")
                logger.debug(f"Wallet {wallet_index} | Response: {json.dumps(data, indent=2)}")
        except Exception as e:
            logger.error(f"Wallet {wallet_index} | Error parsing campaign status: {str(e)}")
            logger.debug(f"Wallet {wallet_index} | Response: {response.text}")
    
    except Exception as e:
        logger.error(f"Wallet {wallet_index} | Failed to get campaign status: {str(e)}")
    
    # Default values if anything fails
    return {"joined": False, "completed_missions": 0, "total_missions": 0, "balance": 0}

# Mission functions
def get_available_missions(auth_headers, wallet_index, proxy=None):
    """Get list of available missions for the authenticated wallet"""
    timestamp = int(time.time() * 1000)
    
    # Try multiple API endpoints for missions
    endpoints = [
        # Alternative endpoint without date filter (to avoid format issues)
        f"{BASE_URL}/questing/missions?filter[campaignId]={CAMPAIGN_ID}&filter[status]=AVAILABLE",
        
        # Format date as ISO string for compatibility
        f"{BASE_URL}/questing/missions?filter[campaignId]={CAMPAIGN_ID}&filter[status]=AVAILABLE&filter[grouped]=true&filter[progress]=true&filter[rewards]=true",
    ]
    
    for url in endpoints:
        logger.debug(f"Wallet {wallet_index} | Trying to fetch missions from: {url}")
        
        try:
            response = make_request('GET', url, wallet_index, proxy=proxy, headers=auth_headers)
            
            data = response.json()
            missions = data.get("data", [])
            
            if missions:
                logger.info(f"Wallet {wallet_index} | Found {len(missions)} missions")
                return missions
            else:
                logger.debug(f"Wallet {wallet_index} | No missions found at this endpoint")
        
        except Exception as e:
            logger.warning(f"Wallet {wallet_index} | Error fetching missions from endpoint: {str(e)}")
    
    logger.warning(f"Wallet {wallet_index} | Could not find any missions using any endpoint")
    return []

def get_mission_details(auth_headers, mission_id, wallet_index, proxy=None):
    """Get detailed information about a specific mission"""
    url = f"{BASE_URL}/questing/mission/{mission_id}"
    
    try:
        response = make_request('GET', url, wallet_index, proxy=proxy, headers=auth_headers)
        
        mission_data = response.json()
        logger.debug(f"Wallet {wallet_index} | Mission details for {mission_id}: {json.dumps(mission_data, indent=2)}")
        return mission_data
    
    except Exception as e:
        logger.warning(f"Wallet {wallet_index} | Failed to get mission details for {mission_id}: {str(e)}")
        return None

def get_completed_missions(auth_headers, wallet_index, proxy=None):
    """Get list of missions already completed by the authenticated wallet"""
    url = f"{BASE_URL}/questing/missions?filter[status]=COMPLETED&filter[campaignId]={CAMPAIGN_ID}"
    
    try:
        response = make_request('GET', url, wallet_index, proxy=proxy, headers=auth_headers)
        
        completed_missions = response.json().get("data", [])
        logger.info(f"Wallet {wallet_index} | Found {len(completed_missions)} completed missions")
        return completed_missions
    
    except Exception as e:
        logger.warning(f"Wallet {wallet_index} | Failed to get completed missions: {str(e)}")
        return []

def is_mission_supported(mission, wallet_index):
    """Check if mission type is supported for automatic completion"""
    mission_type = mission.get("type")
    mission_label = mission.get("label", "Unknown")
    
    # Explicitly skip invite-related missions without logging
    if mission_type in ["INVITE_USER"] or "invite" in mission_label.lower():
        return False
    
    # Original supported mission types
    if mission_type in SUPPORTED_MISSION_TYPES or mission_type == "NO_TRACK":
        logger.info(f"Wallet {wallet_index} | Mission '{mission_label}' (type: {mission_type}) is supported")
        return True
    
    # Silently skip unsupported mission types
    return False

def complete_mission(auth_headers, mission, wallet_index, proxy=None):
    """Attempt to complete a mission"""
    mission_id = mission["id"]
    mission_label = mission.get("label", "Unknown Mission")
    mission_type = mission.get("type")
    
    # Skip unsupported mission types silently
    if not is_mission_supported(mission, wallet_index):
        return False
    
    # Step 1: Mark mission as active/engaged
    activity_url = f"{BASE_URL}/questing/mission-activity/{mission_id}"
    
    try:
        logger.info(f"Wallet {wallet_index} | Engaging with mission: {mission_label}")
        
        try:
            activity_response = make_request('POST', activity_url, wallet_index, proxy=proxy, headers=auth_headers)
            logger.success(f"Wallet {wallet_index} | Successfully engaged with mission: {mission_label}")
        except Exception as e:
            logger.error(f"Wallet {wallet_index} | Failed to engage with mission: {str(e)}")
            return False
        
        time.sleep(SLEEP_BETWEEN_REQUESTS)
        
        # Step 2: Claim the reward
        reward_url = f"{BASE_URL}/questing/mission-reward/{mission_id}"
        logger.info(f"Wallet {wallet_index} | Claiming reward for mission: {mission_label}")
        
        try:
            reward_response = make_request('POST', reward_url, wallet_index, proxy=proxy, headers=auth_headers)
            logger.success(f"Wallet {wallet_index} | Successfully claimed reward for mission: {mission_label}")
            return True
        except Exception as e:
            logger.error(f"Wallet {wallet_index} | Failed to claim reward: {str(e)}")
            return False
    
    except Exception as e:
        logger.error(f"Wallet {wallet_index} | Error completing mission {mission_label}: {str(e)}")
        return False

def find_working_proxy(proxies, wallet_index, max_attempts=3):
    """Find a working proxy from the list by testing them"""
    if not proxies:
        return None
    
    # Create a copy of the list to avoid modifying the original
    available_proxies = proxies.copy()
    random.shuffle(available_proxies)
    
    # Try proxies until we find a working one or run out
    attempts = 0
    while available_proxies and attempts < max_attempts:
        proxy = available_proxies.pop(0)
        
        if verify_proxy(proxy, wallet_index):
            return proxy
        
        attempts += 1
    
    logger.warning(f"Wallet {wallet_index} | Couldn't find a working proxy after {attempts} attempts")
    return None

# Main automation function
def process_wallet(private_key, wallet_index, proxy=None, backup_proxies=None):
    """Process all operations for a single wallet"""
    logger.info(f"Wallet {wallet_index} | Starting AIDA automation...")
    
    if proxy:
        logger.info(f"Wallet {wallet_index} | Using proxy: {proxy}")
        
        # Verify if the proxy is working
        if not verify_proxy(proxy, wallet_index) and backup_proxies:
            logger.warning(f"Wallet {wallet_index} | Primary proxy not working, searching for alternative...")
            proxy = find_working_proxy(backup_proxies, wallet_index)
            
            if not proxy:
                logger.error(f"Wallet {wallet_index} | No working proxy found. Continuing without proxy.")
    
    # Initialize retry counter for the whole wallet process
    wallet_retries = 0
    max_wallet_retries = 3
    
    while wallet_retries < max_wallet_retries:
        try:
            # Authenticate wallet
            auth_headers, wallet_address = authenticate(private_key, wallet_index, proxy)
            if not auth_headers:
                logger.error(f"Wallet {wallet_index} | Authentication failed. Retrying...")
                wallet_retries += 1
                time.sleep(RETRY_DELAY * wallet_retries)
                continue
            
            logger.info(f"Wallet {wallet_index} | Processing wallet: {wallet_address}")
            
            # Join campaign 
            join_result = join_campaign(auth_headers, wallet_index, proxy)
            if not join_result:
                logger.error(f"Wallet {wallet_index} | Failed to join campaign. Retrying...")
                wallet_retries += 1
                time.sleep(RETRY_DELAY * wallet_retries)
                continue
            
            # Check campaign status
            logger.info(f"Wallet {wallet_index} | Checking campaign status...")
            campaign_status = get_campaign_status(auth_headers, wallet_index, proxy)
            
            logger.info(f"Wallet {wallet_index} | Campaign joined: {campaign_status['joined']}")
            logger.info(f"Wallet {wallet_index} | Campaign progress: {campaign_status['completed_missions']}/{campaign_status['total_missions']} missions completed")
            logger.info(f"Wallet {wallet_index} | Current balance: {campaign_status['balance']} tokens")
            
            # Process available missions
            logger.info(f"Wallet {wallet_index} | Processing available missions...")
            available_missions = get_available_missions(auth_headers, wallet_index, proxy)
            
            if not available_missions:
                logger.warning(f"Wallet {wallet_index} | No available missions found.")
                break  # No need to retry, just no missions available
            
            # Get already completed missions
            completed_missions = get_completed_missions(auth_headers, wallet_index, proxy)
            completed_mission_ids = [mission["id"] for mission in completed_missions]
            
            # Process each mission
            missions_completed = 0
            for mission in available_missions:
                mission_id = mission["id"]
                mission_label = mission.get("label", "Unknown Mission")
                
                # Skip if mission is already completed
                if mission_id in completed_mission_ids:
                    continue
                
                # Skip any invite-related missions without logging
                if "invite" in mission_label.lower():
                    continue
                
                logger.info(f"Wallet {wallet_index} | Processing mission: {mission_label} (ID: {mission_id})")
                
                # Add retries for mission completion
                mission_retries = 0
                while mission_retries < 3:
                    try:
                        success = complete_mission(auth_headers, mission, wallet_index, proxy)
                        
                        if success:
                            missions_completed += 1
                            logger.success(f"Wallet {wallet_index} | Successfully completed mission: {mission_label}")
                            break
                        else:
                            logger.warning(f"Wallet {wallet_index} | Failed to complete mission: {mission_label}")
                            mission_retries += 1
                            if mission_retries < 3:
                                logger.info(f"Wallet {wallet_index} | Retrying mission {mission_retries}/3...")
                                time.sleep(RETRY_DELAY)
                    except Exception as e:
                        logger.error(f"Wallet {wallet_index} | Error completing mission: {str(e)}")
                        mission_retries += 1
                        if mission_retries < 3:
                            logger.info(f"Wallet {wallet_index} | Retrying mission {mission_retries}/3...")
                            time.sleep(RETRY_DELAY)
                
                time.sleep(SLEEP_BETWEEN_REQUESTS)
            
            # Final status check
            logger.info(f"Wallet {wallet_index} | Checking final campaign status...")
            campaign_status = get_campaign_status(auth_headers, wallet_index, proxy)
            logger.success(f"Wallet {wallet_index} | Automation completed!")
            logger.info(f"Wallet {wallet_index} | Campaign progress: {campaign_status['completed_missions']}/{campaign_status['total_missions']} missions completed")
            logger.info(f"Wallet {wallet_index} | Current balance: {campaign_status['balance']} tokens")
            logger.info(f"Wallet {wallet_index} | Newly completed missions: {missions_completed}")
            
            # If we got here, we've successfully processed the wallet
            break
            
        except Exception as e:
            logger.error(f"Wallet {wallet_index} | Error processing wallet: {str(e)}")
            wallet_retries += 1
            
            if wallet_retries < max_wallet_retries:
                logger.info(f"Wallet {wallet_index} | Retrying wallet processing ({wallet_retries}/{max_wallet_retries})...")
                
                # If we have backup proxies and current proxy seems to be the issue
                if backup_proxies and ("proxy" in str(e).lower() or "timeout" in str(e).lower() or "connection" in str(e).lower()):
                    logger.info(f"Wallet {wallet_index} | Trying to find a new proxy...")
                    proxy = find_working_proxy(backup_proxies, wallet_index)
                
                # Exponential backoff for retries
                backoff_time = RETRY_DELAY * (2 ** wallet_retries)
                logger.info(f"Wallet {wallet_index} | Waiting {backoff_time} seconds before retry...")
                time.sleep(backoff_time)
            else:
                logger.error(f"Wallet {wallet_index} | Failed to process wallet after {max_wallet_retries} attempts")
                import traceback
                logger.debug(traceback.format_exc())

def run_automation():
    """Main function to run the automation for all wallets"""
    logger.info("=" * 50)
    logger.info("AIDA PLATFORM AUTOMATION")
    logger.info("=" * 50)
    
    # Get all private keys
    private_keys = get_private_keys()
    logger.info(f"Found {len(private_keys)} wallet(s) to process")
    
    # Get all proxies
    proxies = get_proxies()
    logger.info(f"Found {len(proxies)} proxy/proxies to use")
    
    # Process each wallet
    for i, private_key in enumerate(private_keys):
        wallet_index = i + 1
        
        # Assign primary proxy to wallet if available
        primary_proxy = None
        if i < len(proxies):
            primary_proxy = proxies[i]
        
        # Create a list of backup proxies (all proxies except the primary one)
        backup_proxies = [p for p in proxies if p != primary_proxy]
        
        logger.info("=" * 50)
        logger.info(f"PROCESSING WALLET {wallet_index}/{len(private_keys)}")
        if primary_proxy:
            logger.info(f"WITH PRIMARY PROXY: {primary_proxy}")
            logger.info(f"BACKUP PROXIES AVAILABLE: {len(backup_proxies)}")
        logger.info("=" * 50)
        
        try:
            process_wallet(private_key, wallet_index, primary_proxy, backup_proxies)
        except Exception as e:
            logger.error(f"Wallet {wallet_index} | Critical error processing wallet: {str(e)}")
            import traceback
            logger.debug(traceback.format_exc())
        
        logger.info(f"Wallet {wallet_index} | Completed processing")
        
        # Add delay between processing wallets
        if i < len(private_keys) - 1:
            delay = 5 + random.uniform(0, 2)  # Add some randomness to avoid patterns
            logger.info(f"Waiting {delay:.2f} seconds before processing next wallet...")
            time.sleep(delay)
    
    logger.success("All wallets processed. Automation completed!")

if __name__ == "__main__":
    try:
        timestamp = datetime.now().strftime("%m/%d/%YYYY - %H:%M:%S")
        logger.info(f"Starting automation at {timestamp}")
        run_automation()
    except KeyboardInterrupt:
        logger.warning("\nOperation cancelled by user.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}")
        import traceback
        logger.debug(traceback.format_exc())
