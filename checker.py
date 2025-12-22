"""
Apple ID Account Status Checker
Проверяет статус аккаунтов и распределяет по категориям
"""

import os
import time
import json
import re
import logging
import urllib.parse
import tls_client
from datetime import datetime
from threading import Lock

lock = Lock()

# Logging configuration
LOG_FILE = f'files/logs/checker_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load settings
try:
    with open('files/settings.json', 'r') as f:
        settings = json.load(f)
except:
    settings = {}
    logger.error("Could not load settings.json")


class AccountStatus:
    """Account status constants"""
    VALID = "valid"
    VALID_2FA = "valid_2fa"
    INVALID = "invalid"
    LOCKED = "locked"
    TEMP_LOCKED = "temp_locked"
    INACTIVE = "inactive"
    RATE_LIMITED = "rate_limited"
    UNKNOWN = "unknown"
    
    DESCRIPTIONS = {
        VALID: "Valid - can change password via security questions",
        VALID_2FA: "Valid - requires 2FA",
        INVALID: "Invalid - Apple ID does not exist",
        LOCKED: "Locked - permanent lock",
        TEMP_LOCKED: "Temp Locked - temporary lock",
        INACTIVE: "Inactive - account disabled",
        RATE_LIMITED: "Rate Limited - too many requests",
        UNKNOWN: "Unknown status"
    }
    
    # Apple error codes mapping
    ERROR_CODES = {
        "-20101": INVALID,
        "-20209": LOCKED,
        "-20283": LOCKED,
        "-20210": INACTIVE,
        "-20751": INACTIVE,
    }


class CaptchaSolver:
    """Captcha solving via YesCaptcha API"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
    
    def solve(self, image_base64: str) -> str:
        """Solve captcha and return answer"""
        try:
            from yescaptcha.task import ImageToTextTask
            from yescaptcha.client import Client
            
            client = Client(client_key=self.api_key)
            task = ImageToTextTask(image_base64)
            job = client.create_task(task)
            return job.get_solution_text()
        except Exception as e:
            logger.error(f"Captcha error: {e}")
            return None


class AppleIDChecker:
    """Apple ID account status checker"""
    
    def __init__(self):
        api_key = settings.get('api_key') or settings.get('API_KEY', '')
        self.captcha_solver = CaptchaSolver(api_key) if api_key else None
        
        self.session = None
        self.headers = {}
        self.sstt_token = None
    
    def _init_session(self):
        """Initialize TLS session"""
        self.session = tls_client.Session(
            client_identifier="chrome_120",
            random_tls_extension_order=True
        )
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'en-US,en;q=0.9',
            'Content-Type': 'application/json',
            'Origin': 'https://iforgot.apple.com',
            'Referer': 'https://iforgot.apple.com/',
            'X-Requested-With': 'XMLHttpRequest',
        }
    
    def _update_sstt(self, resp):
        """Update sstt token from response"""
        if 'Sstt' in resp.headers:
            self.headers['sstt'] = resp.headers['Sstt']
            return True
        return False
    
    def check(self, email: str) -> str:
        """
        Check account status
        Returns: AccountStatus constant
        """
        logger.info(f"[{email}] Checking account...")
        self._init_session()
        
        # Step 1: Load initial page
        resp = self.session.get(
            'https://iforgot.apple.com/password/verify/appleid',
            headers=self.headers
        )
        
        if resp.status_code != 200:
            logger.error(f"[{email}] Failed to load page: {resp.status_code}")
            return AccountStatus.UNKNOWN
        
        # Extract sstt token
        match = re.search(r'"sstt"\s*:\s*"([^"]+)"', resp.text)
        if not match:
            logger.error(f"[{email}] Could not extract sstt token")
            return AccountStatus.UNKNOWN
        
        self.sstt_token = urllib.parse.quote(match.group(1))
        self.headers['sstt'] = self.sstt_token
        self.headers['cookie'] = '; '.join([f"{k}={v}" for k, v in resp.cookies.items()])
        
        # Step 2: Get and solve captcha
        captcha_info = self._get_and_solve_captcha(email)
        if not captcha_info:
            return AccountStatus.UNKNOWN
        
        # Step 3: Verify Apple ID
        return self._verify_apple_id(email, captcha_info)
    
    def _get_and_solve_captcha(self, email: str) -> dict:
        """Get captcha and solve it"""
        if not self.captcha_solver:
            logger.error(f"[{email}] No captcha solver configured")
            return None
        
        for attempt in range(3):
            resp = self.session.get(
                'https://iforgot.apple.com/captcha?captchaType=IMAGE',
                headers=self.headers
            )
            
            if resp.status_code == 503:
                logger.warning(f"[{email}] Rate limited")
                return None
            
            if resp.status_code in [200, 401]:
                try:
                    data = resp.json()
                    captcha_id = data.get('id', '')
                    captcha_token = data.get('token', '')
                    
                    image_b64 = None
                    if 'captcha' in data:
                        image_b64 = data['captcha']
                    elif 'payload' in data and 'content' in data['payload']:
                        image_b64 = data['payload']['content']
                    
                    if image_b64:
                        if 'base64,' in image_b64:
                            image_b64 = image_b64.split('base64,')[1]
                        
                        answer = self.captcha_solver.solve(image_b64)
                        if answer:
                            logger.info(f"[{email}] Captcha solved: {answer}")
                            return {
                                'id': captcha_id,
                                'token': captcha_token,
                                'answer': answer
                            }
                except Exception as e:
                    logger.error(f"[{email}] Captcha parse error: {e}")
            
            time.sleep(1)
        
        logger.error(f"[{email}] Failed to solve captcha")
        return None
    
    def _verify_apple_id(self, email: str, captcha_info: dict) -> str:
        """Verify Apple ID and determine status"""
        verify_data = {
            "id": email,
            "captcha": {
                "id": captcha_info['id'],
                "answer": captcha_info['answer'],
                "token": captcha_info['token']
            }
        }
        
        resp = self.session.post(
            'https://iforgot.apple.com/password/verify/appleid',
            headers=self.headers,
            json=verify_data
        )
        
        self._update_sstt(resp)
        
        # Rate limited
        if resp.status_code == 503:
            return AccountStatus.RATE_LIMITED
        
        # Error response
        if resp.status_code in [400, 401, 403, 423]:
            return self._parse_error_response(email, resp)
        
        # Success - continue to check for temp lock
        if resp.status_code == 302:
            return self._deep_check(email, resp)
        
        logger.warning(f"[{email}] Unknown status: {resp.status_code}")
        return AccountStatus.UNKNOWN
    
    def _parse_error_response(self, email: str, resp) -> str:
        """Parse error response and return status"""
        try:
            data = resp.json()
            errors = data.get('service_errors') or data.get('serviceErrors', [])
            
            for err in errors:
                code = str(err.get('code', ''))
                message = err.get('message', '')
                logger.info(f"[{email}] Error: {code} - {message}")
                
                if code in AccountStatus.ERROR_CODES:
                    return AccountStatus.ERROR_CODES[code]
            
            return AccountStatus.UNKNOWN
        except:
            return AccountStatus.UNKNOWN
    
    def _deep_check(self, email: str, verify_resp) -> str:
        """Continue flow to detect temporary locks"""
        location = verify_resp.headers.get('Location', '')
        if not location:
            return AccountStatus.UNKNOWN
        
        # Get recovery options / auth method
        resp = self.session.get(
            f'https://iforgot.apple.com{location}',
            headers=self.headers
        )
        
        if 'session/timeout' in str(resp.url):
            return AccountStatus.TEMP_LOCKED
        
        self._update_sstt(resp)
        
        try:
            data = resp.json()
            if 'sstt' in data:
                self.headers['sstt'] = urllib.parse.quote(data['sstt'])
            
            # Check for 2FA
            auth_methods = data.get('authenticationMethods', [])
            if 'hsa2' in auth_methods or 'trustedDevices' in auth_methods:
                return AccountStatus.VALID_2FA
        except:
            pass
        
        # Try to select reset_password option
        resp = self.session.post(
            'https://iforgot.apple.com/recovery/options',
            headers=self.headers,
            json={"option": "reset_password"}
        )
        
        if resp.status_code == 302:
            location = resp.headers.get('Location', '')
            if 'session/timeout' in location:
                return AccountStatus.TEMP_LOCKED
        
        self._update_sstt(resp)
        
        # Get auth method
        if resp.status_code == 302 and 'Location' in resp.headers:
            resp = self.session.get(
                f'https://iforgot.apple.com{resp.headers["Location"]}',
                headers=self.headers
            )
        else:
            resp = self.session.get(
                'https://iforgot.apple.com/password/authenticationmethod',
                headers=self.headers
            )
        
        if 'session/timeout' in str(resp.url):
            return AccountStatus.TEMP_LOCKED
        
        self._update_sstt(resp)
        
        # Select questions method
        resp = self.session.post(
            'https://iforgot.apple.com/password/authenticationmethod',
            headers=self.headers,
            json={"type": "questions"}
        )
        
        if resp.status_code == 302:
            location = resp.headers.get('Location', '')
            if 'session/timeout' in location:
                return AccountStatus.TEMP_LOCKED
        
        self._update_sstt(resp)
        
        # Get birthday page
        if resp.status_code == 302 and 'Location' in resp.headers:
            resp = self.session.get(
                f'https://iforgot.apple.com{resp.headers["Location"]}',
                headers=self.headers
            )
        else:
            resp = self.session.get(
                'https://iforgot.apple.com/password/verify/birthday',
                headers=self.headers
            )
        
        if 'session/timeout' in str(resp.url):
            return AccountStatus.TEMP_LOCKED
        
        if 'Sstt' in resp.headers:
            return AccountStatus.VALID
        
        try:
            data = resp.json()
            if 'dateLayout' in data or 'sstt' in data:
                return AccountStatus.VALID
        except:
            pass
        
        if not resp.text or resp.text == '{}':
            return AccountStatus.TEMP_LOCKED
        
        return AccountStatus.VALID


class AccountManager:
    """Manages account checking and sorting"""
    
    def __init__(self):
        self.checker = AppleIDChecker()
        self.results = {status: [] for status in [
            AccountStatus.VALID,
            AccountStatus.VALID_2FA,
            AccountStatus.INVALID,
            AccountStatus.LOCKED,
            AccountStatus.TEMP_LOCKED,
            AccountStatus.INACTIVE,
            AccountStatus.RATE_LIMITED,
            AccountStatus.UNKNOWN
        ]}
    
    def check_account(self, account_line: str) -> str:
        """Check single account and categorize"""
        parts = account_line.strip().split(',')
        if len(parts) < 1:
            return AccountStatus.UNKNOWN
        
        email = parts[0].strip()
        status = self.checker.check(email)
        
        self.results[status].append(account_line)
        return status
    
    def check_all(self, accounts: list):
        """Check all accounts"""
        total = len(accounts)
        
        for i, account in enumerate(accounts, 1):
            email = account.split(',')[0].strip()
            print(f"\n[{i}/{total}] Checking: {email}")
            
            status = self.check_account(account)
            desc = AccountStatus.DESCRIPTIONS.get(status, status)
            print(f"  Result: {desc}")
            
            if i < total:
                time.sleep(1)
    
    def save_results(self):
        """Save results to separate files by status"""
        output_dir = 'files/results'
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        for status, accounts in self.results.items():
            if accounts:
                filepath = f'{output_dir}/{status}.txt'
                with open(filepath, 'w', encoding='utf-8') as f:
                    for acc in accounts:
                        f.write(f"{acc} | {timestamp}\n")
                logger.info(f"Saved {len(accounts)} accounts to {filepath}")
    
    def print_summary(self):
        """Print summary of results"""
        print("\n" + "="*60)
        print("  RESULTS SUMMARY")
        print("="*60)
        
        for status, accounts in self.results.items():
            if accounts:
                desc = AccountStatus.DESCRIPTIONS.get(status, status)
                print(f"\n[{status.upper()}] {desc}: {len(accounts)}")
                for acc in accounts:
                    email = acc.split(',')[0].strip()
                    print(f"  - {email}")
        
        print("\n" + "="*60)
        print(f"Results saved to: files/results/")
        print(f"Log file: {LOG_FILE}")
        print("="*60)


def main():
    print("="*60)
    print("  Apple ID Account Status Checker")
    print("="*60)
    
    # Read accounts
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
    print(f"Log file: {LOG_FILE}")
    
    manager = AccountManager()
    manager.check_all(accounts)
    manager.save_results()
    manager.print_summary()


if __name__ == '__main__':
    main()
