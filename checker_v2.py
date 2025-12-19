"""
Apple ID Account Status Checker v2
С детальным debug логированием

Ожидаемые результаты:
- eqnvsyvpws@outlook.com -> inactive (полный бан / неактивен)
- EnolaPalaspas618@hotmail.com -> valid (все хорошо)
- wyszkowski18590@outlook.com -> temp_locked (временная блокировка IP)
"""

import os
import time
import json
import re
import logging
import urllib.parse
import tls_client
from datetime import datetime
from colorama import Fore, init
from threading import Lock

init()
lock = Lock()

# Create debug log file with timestamp
DEBUG_FILE = f'files/checker_debug_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'

# Logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(DEBUG_FILE, encoding='utf-8'),
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

# Account status codes
STATUS_CODES = {
    "valid": "✅ Valid (можно сменить пароль через вопросы)",
    "valid_2fa": "✅ Valid (требуется 2FA)",
    "invalid": "❌ Invalid (Apple ID не существует)",
    "locked": "🔒 Locked (полная блокировка)",
    "temp_locked": "🔐 Temp Locked (временная блокировка IP)",
    "inactive": "⏸️ Inactive (аккаунт неактивен/отключен)",
    "rate_limited": "⏳ Rate Limited (слишком много запросов)",
    "unknown": "❓ Unknown"
}

# Error codes mapping
ERROR_CODES = {
    "-20101": "invalid",      # Apple ID doesn't exist
    "-20209": "locked",       # Account locked
    "-20283": "locked",       # Account locked (another code)
    "-20210": "inactive",     # Account inactive
    "-20751": "inactive",     # Account inactive (another code)
}


def log_response(step_name: str, resp, show_body: bool = True):
    """Log detailed response info"""
    logger.info(f"\n{'='*60}")
    logger.info(f"STEP: {step_name}")
    logger.info(f"{'='*60}")
    logger.info(f"Status Code: {resp.status_code}")
    logger.info(f"URL: {resp.url}")
    
    # Headers
    logger.debug(f"Response Headers:")
    for key, value in resp.headers.items():
        if key.lower() in ['sstt', 'location', 'set-cookie', 'x-apple-i-request-id']:
            logger.info(f"  {key}: {str(value)[:100]}...")
    
    # Body
    if show_body:
        body = resp.text[:500] if resp.text else "(empty)"
        logger.debug(f"Response Body: {body}")
    
    logger.info(f"{'='*60}\n")


class AccountChecker:
    """Apple ID Account Status Checker with debug logging"""
    
    def __init__(self):
        self.results = {
            "valid": [],
            "valid_2fa": [],
            "invalid": [],
            "locked": [],
            "temp_locked": [],
            "inactive": [],
            "rate_limited": [],
            "unknown": []
        }
    
    def check_account(self, account_line: str) -> str:
        """Check single account status"""
        parts = account_line.strip().split(',')
        if len(parts) < 2:
            logger.error(f"Invalid format: {account_line}")
            return "unknown"
        
        email = parts[0].strip()
        
        logger.info(f"\n{'#'*60}")
        logger.info(f"CHECKING: {email}")
        logger.info(f"{'#'*60}")
        
        status = self._check_via_iforgot(email)
        
        # Store result
        self.results[status].append(account_line)
        
        # Log result
        status_text = STATUS_CODES.get(status, status)
        logger.info(f"RESULT: {email} -> {status_text}")
        
        return status
    
    def _solve_captcha(self, image_base64: str) -> str:
        """Solve captcha via YesCaptcha"""
        try:
            from yescaptcha.task import ImageToTextTask
            from yescaptcha.client import Client
            
            api_key = settings.get('api_key') or settings.get('API_KEY', '')
            if not api_key:
                logger.error("No API key for captcha")
                return None
            
            client = Client(client_key=api_key)
            task = ImageToTextTask(image_base64)
            job = client.create_task(task)
            
            # Use get_solution_text() method
            result = job.get_solution_text()
            return result
        except Exception as e:
            logger.error(f"Captcha error: {e}")
            return None
    
    def _check_via_iforgot(self, email: str) -> str:
        """Full check via iforgot.apple.com"""
        
        session = tls_client.Session(
            client_identifier="chrome_120",
            random_tls_extension_order=True
        )
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'en-US,en;q=0.9',
            'Content-Type': 'application/json',
            'Origin': 'https://iforgot.apple.com',
            'Referer': 'https://iforgot.apple.com/',
            'X-Requested-With': 'XMLHttpRequest',
        }
        
        # ============================================================
        # STEP 1: Load initial page, get sstt token
        # ============================================================
        logger.info(f"[{email}] Step 1: Loading initial page...")
        
        resp1 = session.get(
            'https://iforgot.apple.com/password/verify/appleid',
            headers=headers
        )
        log_response("1. Initial Page", resp1, show_body=False)
        
        if resp1.status_code != 200:
            logger.error(f"[{email}] Failed to load initial page: {resp1.status_code}")
            return "unknown"
        
        # Extract sstt token
        match = re.search(r'"sstt"\s*:\s*"([^"]+)"', resp1.text)
        if not match:
            logger.error(f"[{email}] Could not extract sstt token")
            return "unknown"
        
        sstt_token = urllib.parse.quote(match.group(1))
        headers['sstt'] = sstt_token
        logger.info(f"[{email}] Got sstt token: {sstt_token[:50]}...")
        
        # Update cookies
        headers['cookie'] = '; '.join([f"{name}={value}" for name, value in resp1.cookies.items()])
        
        # ============================================================
        # STEP 2: Get and solve captcha
        # ============================================================
        logger.info(f"[{email}] Step 2: Getting captcha...")
        
        captcha_info = None
        for attempt in range(3):
            resp2 = session.get(
                'https://iforgot.apple.com/captcha?captchaType=IMAGE',
                headers=headers
            )
            log_response(f"2. Captcha (attempt {attempt+1})", resp2)
            
            if resp2.status_code == 503:
                logger.warning(f"[{email}] Rate limited on captcha")
                return "rate_limited"
            
            if resp2.status_code in [200, 401]:
                try:
                    captcha_data = resp2.json()
                    image_b64 = None
                    
                    # Get captcha id and token from response
                    captcha_id = captcha_data.get('id', '')
                    captcha_token_from_resp = captcha_data.get('token', '')
                    
                    # Try different captcha response formats
                    if 'captcha' in captcha_data:
                        image_b64 = captcha_data['captcha']
                    elif 'payload' in captcha_data and 'content' in captcha_data['payload']:
                        image_b64 = captcha_data['payload']['content']
                    
                    if image_b64:
                        # Remove data URI prefix if present
                        if 'base64,' in image_b64:
                            image_b64 = image_b64.split('base64,')[1]
                        
                        captcha_answer = self._solve_captcha(image_b64)
                        if captcha_answer:
                            logger.info(f"[{email}] Captcha solved: {captcha_answer}")
                            # Store all captcha info for verify request
                            captcha_info = {
                                'id': captcha_id,
                                'token': captcha_token_from_resp,
                                'answer': captcha_answer
                            }
                            break
                    else:
                        logger.warning(f"[{email}] No captcha image in response")
                except Exception as e:
                    logger.error(f"[{email}] Captcha parse error: {e}")
            
            time.sleep(1)
        
        if 'captcha_info' not in locals() or not captcha_info:
            logger.error(f"[{email}] Failed to solve captcha")
            return "unknown"
        
        # ============================================================
        # STEP 3: Verify Apple ID
        # ============================================================
        logger.info(f"[{email}] Step 3: Verifying Apple ID...")
        
        verify_data = {
            "id": email,
            "captcha": {
                "id": captcha_info['id'],
                "answer": captcha_info['answer'],
                "token": captcha_info['token']
            }
        }
        
        logger.debug(f"[{email}] Verify data: {verify_data}")
        
        resp3 = session.post(
            'https://iforgot.apple.com/password/verify/appleid',
            headers=headers,
            json=verify_data
        )
        log_response("3. Verify Apple ID", resp3)
        
        # Update sstt if present
        if 'Sstt' in resp3.headers:
            headers['sstt'] = resp3.headers['Sstt']
        
        # ============================================================
        # Analyze response
        # ============================================================
        
        # Case 1: Rate limited
        if resp3.status_code == 503:
            logger.info(f"[{email}] -> RATE LIMITED (503)")
            return "rate_limited"
        
        # Case 2: Error response with codes
        if resp3.status_code in [400, 401, 403, 423]:
            try:
                error_data = resp3.json()
                errors = error_data.get('service_errors') or error_data.get('serviceErrors', [])
                
                for err in errors:
                    code = str(err.get('code', ''))
                    message = err.get('message', '')
                    logger.info(f"[{email}] Error code: {code}, message: {message}")
                    
                    if code in ERROR_CODES:
                        status = ERROR_CODES[code]
                        logger.info(f"[{email}] -> {status.upper()} (code {code})")
                        return status
                
                # Unknown error code
                logger.warning(f"[{email}] Unknown error: {error_data}")
                return "unknown"
                
            except Exception as e:
                logger.error(f"[{email}] Error parsing response: {e}")
                return "unknown"
        
        # Case 3: Success - account exists, continue to check for temp lock
        if resp3.status_code == 302:
            logger.info(f"[{email}] Apple ID verified, checking for temp lock...")
            return self._deep_check(email, session, headers, resp3)
        
        # Case 4: Unknown status
        logger.warning(f"[{email}] Unknown status code: {resp3.status_code}")
        return "unknown"
    
    def _deep_check(self, email: str, session, headers: dict, verify_resp) -> str:
        """
        Continue flow to detect temporary locks (session timeout)
        """
        # ============================================================
        # STEP 4: Get recovery options
        # ============================================================
        logger.info(f"[{email}] Step 4: Getting recovery options...")
        
        location = verify_resp.headers.get('Location', '')
        if not location:
            logger.error(f"[{email}] No Location header in verify response")
            return "unknown"
        
        resp4 = session.get(
            f'https://iforgot.apple.com{location}',
            headers=headers
        )
        log_response("4. Recovery Options", resp4)
        
        # Check for session timeout
        if 'session/timeout' in str(resp4.url) or 'session/timeout' in resp4.headers.get('Location', ''):
            logger.info(f"[{email}] -> TEMP LOCKED (session timeout at recovery options)")
            return "temp_locked"
        
        # Update sstt
        if 'Sstt' in resp4.headers:
            headers['sstt'] = resp4.headers['Sstt']
        
        try:
            recovery_data = resp4.json()
            if 'sstt' in recovery_data:
                headers['sstt'] = urllib.parse.quote(recovery_data['sstt'])
            
            logger.info(f"[{email}] Recovery options: {recovery_data.get('recoveryOptions', [])}")
        except:
            pass
        
        # ============================================================
        # STEP 5: Select reset_password option
        # ============================================================
        logger.info(f"[{email}] Step 5: Selecting reset_password...")
        
        resp5 = session.post(
            'https://iforgot.apple.com/recovery/options',
            headers=headers,
            json={"option": "reset_password"}
        )
        log_response("5. Select Option", resp5)
        
        # Check for session timeout
        if resp5.status_code == 302:
            location = resp5.headers.get('Location', '')
            if 'session/timeout' in location:
                logger.info(f"[{email}] -> TEMP LOCKED (session timeout at select option)")
                return "temp_locked"
        
        if 'Sstt' in resp5.headers:
            headers['sstt'] = resp5.headers['Sstt']
        
        # ============================================================
        # STEP 6: Get authentication method
        # ============================================================
        logger.info(f"[{email}] Step 6: Getting auth method...")
        
        if resp5.status_code == 302 and 'Location' in resp5.headers:
            resp6 = session.get(
                f'https://iforgot.apple.com{resp5.headers["Location"]}',
                headers=headers
            )
        else:
            resp6 = session.get(
                'https://iforgot.apple.com/password/authenticationmethod',
                headers=headers
            )
        log_response("6. Auth Method", resp6)
        
        # Check for session timeout
        if 'session/timeout' in str(resp6.url) or 'session/timeout' in resp6.headers.get('Location', ''):
            logger.info(f"[{email}] -> TEMP LOCKED (session timeout at auth method)")
            return "temp_locked"
        
        if 'Sstt' in resp6.headers:
            headers['sstt'] = resp6.headers['Sstt']
        
        try:
            auth_data = resp6.json()
            if 'sstt' in auth_data:
                headers['sstt'] = urllib.parse.quote(auth_data['sstt'])
            
            # Check for 2FA
            auth_methods = auth_data.get('authenticationMethods', [])
            logger.info(f"[{email}] Auth methods: {auth_methods}")
            
            if 'hsa2' in auth_methods or 'trustedDevices' in auth_methods:
                logger.info(f"[{email}] -> VALID (2FA required)")
                return "valid_2fa"
        except:
            pass
        
        # ============================================================
        # STEP 7: Select questions method
        # ============================================================
        logger.info(f"[{email}] Step 7: Selecting questions method...")
        
        resp7 = session.post(
            'https://iforgot.apple.com/password/authenticationmethod',
            headers=headers,
            json={"type": "questions"}
        )
        log_response("7. Select Questions", resp7)
        
        # Check for session timeout
        if resp7.status_code == 302:
            location = resp7.headers.get('Location', '')
            if 'session/timeout' in location:
                logger.info(f"[{email}] -> TEMP LOCKED (session timeout at questions)")
                return "temp_locked"
        
        if 'Sstt' in resp7.headers:
            headers['sstt'] = resp7.headers['Sstt']
        
        # ============================================================
        # STEP 8: Get birthday page (final check)
        # ============================================================
        logger.info(f"[{email}] Step 8: Getting birthday page (final check)...")
        
        if resp7.status_code == 302 and 'Location' in resp7.headers:
            resp8 = session.get(
                f'https://iforgot.apple.com{resp7.headers["Location"]}',
                headers=headers
            )
        else:
            resp8 = session.get(
                'https://iforgot.apple.com/password/verify/birthday',
                headers=headers
            )
        log_response("8. Birthday Page", resp8)
        
        # Check for session timeout
        if 'session/timeout' in str(resp8.url) or 'session/timeout' in resp8.headers.get('Location', ''):
            logger.info(f"[{email}] -> TEMP LOCKED (session timeout at birthday)")
            return "temp_locked"
        
        # If we got Sstt header, account is valid
        if 'Sstt' in resp8.headers:
            logger.info(f"[{email}] -> VALID (got Sstt at birthday, can change password)")
            return "valid"
        
        # Check response content
        try:
            birthday_data = resp8.json()
            if 'dateLayout' in birthday_data or 'sstt' in birthday_data:
                logger.info(f"[{email}] -> VALID (got birthday form)")
                return "valid"
        except:
            pass
        
        # If empty response or no Sstt, likely temp locked
        if not resp8.text or resp8.text == '{}':
            logger.info(f"[{email}] -> TEMP LOCKED (empty response at birthday)")
            return "temp_locked"
        
        logger.info(f"[{email}] -> VALID (passed all checks)")
        return "valid"
    
    def save_results(self):
        """Save results to files"""
        for status, accounts in self.results.items():
            if accounts:
                filename = f'files/check_{status}.txt'
                with open(filename, 'w', encoding='utf-8') as f:
                    for acc in accounts:
                        f.write(f"{acc}\n")
                logger.info(f"Saved {len(accounts)} accounts to {filename}")
    
    def print_summary(self):
        """Print summary of results"""
        print(f"\n{Fore.CYAN}{'='*60}{Fore.RESET}")
        print(f"{Fore.CYAN}  CHECKER RESULTS SUMMARY{Fore.RESET}")
        print(f"{Fore.CYAN}{'='*60}{Fore.RESET}\n")
        
        for status, accounts in self.results.items():
            if accounts:
                color = {
                    'valid': Fore.GREEN,
                    'valid_2fa': Fore.GREEN,
                    'invalid': Fore.RED,
                    'locked': Fore.RED,
                    'temp_locked': Fore.YELLOW,
                    'inactive': Fore.MAGENTA,
                    'rate_limited': Fore.YELLOW,
                    'unknown': Fore.WHITE
                }.get(status, Fore.WHITE)
                
                status_text = STATUS_CODES.get(status, status)
                print(f"{color}{status_text}: {len(accounts)}{Fore.RESET}")
                for acc in accounts:
                    email = acc.split(',')[0]
                    print(f"  - {email}")
        
        print(f"\n{Fore.CYAN}Debug log: {DEBUG_FILE}{Fore.RESET}")


def main():
    print(f"{Fore.CYAN}{'='*60}{Fore.RESET}")
    print(f"{Fore.CYAN}  Apple ID Account Checker v2 (with Debug){Fore.RESET}")
    print(f"{Fore.CYAN}{'='*60}{Fore.RESET}\n")
    
    # Read accounts
    try:
        with open('files/Accounts.txt', 'r', encoding='utf-8') as f:
            accounts = [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}Error: files/Accounts.txt not found{Fore.RESET}")
        return
    
    if not accounts:
        print(f"{Fore.YELLOW}No accounts to check{Fore.RESET}")
        return
    
    print(f"Found {len(accounts)} account(s)")
    print(f"Debug log: {DEBUG_FILE}\n")
    
    checker = AccountChecker()
    
    for i, account in enumerate(accounts, 1):
        email = account.split(',')[0]
        print(f"\n{Fore.YELLOW}[{i}/{len(accounts)}] Checking: {email}{Fore.RESET}")
        
        status = checker.check_account(account)
        status_text = STATUS_CODES.get(status, status)
        
        color = {
            'valid': Fore.GREEN,
            'valid_2fa': Fore.GREEN,
            'invalid': Fore.RED,
            'locked': Fore.RED,
            'temp_locked': Fore.YELLOW,
            'inactive': Fore.MAGENTA,
            'rate_limited': Fore.YELLOW,
        }.get(status, Fore.WHITE)
        
        print(f"{color}Result: {status_text}{Fore.RESET}")
        
        # Small delay between accounts
        if i < len(accounts):
            time.sleep(1)
    
    # Save and print summary
    checker.save_results()
    checker.print_summary()


if __name__ == '__main__':
    main()
