"""
Flow для смены пароля ЗАБЛОКИРОВАННОГО аккаунта Apple ID
Заблокированные аккаунты требуют другой процесс восстановления

ВАЖНО: Заблокированные аккаунты (код -20209, -20283) НЕ могут использовать
секретные вопросы для восстановления. Apple требует:
1. Подтверждение через доверенное устройство
2. Подтверждение через номер телефона
3. Обращение в поддержку Apple

Этот модуль определяет статус блокировки и предлагает варианты действий.

Типы блокировок:
- Permanent Lock (-20209, -20283): Полная блокировка, требует обращения в Apple
- Temporary Lock (session/timeout): Временная блокировка IP, нужно сменить IP/VPN
- Inactive (-20210, -20751): Аккаунт неактивен/отключен
"""

import os
import time
import json
import logging
import urllib.parse
import tls_client
from colorama import Fore, init
from threading import Lock

init()
lock = Lock()

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('files/flow_locked.log'),
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

# Lock status codes
LOCK_STATUS = {
    "permanent_lock": {
        "codes": ["-20209", "-20283"],
        "description": "Аккаунт заблокирован навсегда",
        "action": "Требуется обращение в поддержку Apple или восстановление через доверенное устройство"
    },
    "temporary_lock": {
        "codes": ["session/timeout"],
        "description": "Временная блокировка IP",
        "action": "Смените IP адрес (VPN) и попробуйте снова"
    },
    "inactive": {
        "codes": ["-20210", "-20751"],
        "description": "Аккаунт неактивен/отключен",
        "action": "Аккаунт был деактивирован владельцем или Apple"
    },
    "invalid": {
        "codes": ["-20101"],
        "description": "Apple ID не существует",
        "action": "Проверьте правильность email адреса"
    },
    "rate_limited": {
        "codes": ["503"],
        "description": "Слишком много запросов",
        "action": "Подождите несколько минут и попробуйте снова"
    }
}


class LockedAccountFlow:
    """Flow для проверки и обработки заблокированных аккаунтов"""
    
    def __init__(self, account_data: str):
        """
        account_data format: email,password,ans1,ans2,ans3,MM/DD/YYYY
        """
        self.data = account_data
        parts = account_data.split(',')
        self.email = parts[0].strip()
        self.password = parts[1].strip() if len(parts) > 1 else ''
        
        # Setup session
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
        
        self.sstt_token = None
    
    def _solve_captcha(self, image_base64: str) -> str:
        """Solve captcha using YesCaptcha"""
        try:
            from yescaptcha.task import ImageToTextTask
            from yescaptcha.client import Client
            
            api_key = settings.get('api_key') or settings.get('API_KEY', '')
            if not api_key:
                logger.error(f"[{self.email}] No API key for captcha")
                return None
            
            client = Client(api_key)
            task = ImageToTextTask(image_base64)
            job = client.create_task(task)
            result = job.join()
            return result.solution.text
        except Exception as e:
            logger.error(f"[{self.email}] Captcha error: {e}")
            return None
    
    def check_lock_status(self) -> dict:
        """
        Check the lock status of the account
        Returns: {
            'status': str,  # permanent_lock, temporary_lock, inactive, invalid, rate_limited, unlocked
            'code': str,    # Error code from Apple
            'message': str, # Human readable message
            'action': str,  # Recommended action
            'can_unlock': bool  # Whether account can be unlocked via questions
        }
        """
        logger.info(f"[{self.email}] Checking lock status...")
        
        try:
            # Step 1: Load initial page
            resp = self.session.get(
                'https://iforgot.apple.com/password/verify/appleid',
                headers=self.headers
            )
            
            if resp.status_code != 200:
                return {
                    'status': 'error',
                    'code': str(resp.status_code),
                    'message': f'Failed to load page: {resp.status_code}',
                    'action': 'Try again later',
                    'can_unlock': False
                }
            
            # Extract sstt token
            import re
            match = re.search(r'"sstt"\s*:\s*"([^"]+)"', resp.text)
            if match:
                self.sstt_token = urllib.parse.quote(match.group(1))
                self.headers['sstt'] = self.sstt_token
            
            # Step 2: Get and solve captcha
            logger.info(f"[{self.email}] Getting captcha...")
            
            captcha_token = None
            for attempt in range(3):
                captcha_resp = self.session.get(
                    'https://iforgot.apple.com/captcha?captchaType=IMAGE',
                    headers=self.headers
                )
                
                if captcha_resp.status_code in [200, 401]:
                    try:
                        captcha_data = captcha_resp.json()
                        if 'captcha' in captcha_data:
                            image_b64 = captcha_data['captcha'].replace('data:image/jpeg;base64,', '')
                            captcha_token = self._solve_captcha(image_b64)
                            if captcha_token:
                                logger.info(f"[{self.email}] Captcha solved")
                                break
                    except:
                        pass
                time.sleep(1)
            
            if not captcha_token:
                return {
                    'status': 'error',
                    'code': 'captcha_failed',
                    'message': 'Failed to solve captcha',
                    'action': 'Check YesCaptcha API key and balance',
                    'can_unlock': False
                }
            
            # Step 3: Verify Apple ID
            logger.info(f"[{self.email}] Verifying Apple ID...")
            
            verify_data = {
                "id": self.email,
                "captcha": {
                    "id": "",
                    "token": captcha_token
                }
            }
            
            verify_resp = self.session.post(
                'https://iforgot.apple.com/password/verify/appleid',
                headers=self.headers,
                json=verify_data
            )
            
            # Analyze response
            if verify_resp.status_code == 302:
                # Account exists and is not locked at this stage
                # Need to continue flow to check for temporary locks
                return self._check_deep_lock_status(verify_resp)
            
            elif verify_resp.status_code == 503:
                return {
                    'status': 'rate_limited',
                    'code': '503',
                    'message': LOCK_STATUS['rate_limited']['description'],
                    'action': LOCK_STATUS['rate_limited']['action'],
                    'can_unlock': False
                }
            
            else:
                # Check for error codes
                try:
                    error_data = verify_resp.json()
                    errors = error_data.get('service_errors') or error_data.get('serviceErrors', [])
                    
                    for err in errors:
                        code = str(err.get('code', ''))
                        message = err.get('message', '')
                        
                        # Check permanent lock
                        if code in LOCK_STATUS['permanent_lock']['codes']:
                            return {
                                'status': 'permanent_lock',
                                'code': code,
                                'message': f"{LOCK_STATUS['permanent_lock']['description']}: {message}",
                                'action': LOCK_STATUS['permanent_lock']['action'],
                                'can_unlock': False
                            }
                        
                        # Check inactive
                        if code in LOCK_STATUS['inactive']['codes']:
                            return {
                                'status': 'inactive',
                                'code': code,
                                'message': f"{LOCK_STATUS['inactive']['description']}: {message}",
                                'action': LOCK_STATUS['inactive']['action'],
                                'can_unlock': False
                            }
                        
                        # Check invalid
                        if code in LOCK_STATUS['invalid']['codes']:
                            return {
                                'status': 'invalid',
                                'code': code,
                                'message': f"{LOCK_STATUS['invalid']['description']}: {message}",
                                'action': LOCK_STATUS['invalid']['action'],
                                'can_unlock': False
                            }
                    
                    # Unknown error
                    return {
                        'status': 'unknown',
                        'code': str(verify_resp.status_code),
                        'message': f'Unknown error: {error_data}',
                        'action': 'Check the error details',
                        'can_unlock': False
                    }
                    
                except:
                    return {
                        'status': 'unknown',
                        'code': str(verify_resp.status_code),
                        'message': f'Failed to parse response: {verify_resp.text[:200]}',
                        'action': 'Check the response',
                        'can_unlock': False
                    }
        
        except Exception as e:
            logger.error(f"[{self.email}] Error: {e}")
            return {
                'status': 'error',
                'code': 'exception',
                'message': str(e),
                'action': 'Check logs for details',
                'can_unlock': False
            }
    
    def _check_deep_lock_status(self, verify_resp) -> dict:
        """
        Continue flow to check for temporary locks (session timeout)
        This happens when Apple allows initial verification but blocks later steps
        """
        logger.info(f"[{self.email}] Checking for temporary lock (deep check)...")
        
        try:
            # Get recovery options
            location = verify_resp.headers.get('Location', '')
            recovery_resp = self.session.get(
                f'https://iforgot.apple.com{location}',
                headers=self.headers
            )
            
            # Check for session timeout in URL
            if 'session/timeout' in str(recovery_resp.url):
                return {
                    'status': 'temporary_lock',
                    'code': 'session/timeout',
                    'message': LOCK_STATUS['temporary_lock']['description'],
                    'action': LOCK_STATUS['temporary_lock']['action'],
                    'can_unlock': False
                }
            
            # Update sstt
            if 'Sstt' in recovery_resp.headers:
                self.headers['sstt'] = recovery_resp.headers['Sstt']
            
            try:
                recovery_data = recovery_resp.json()
                if 'sstt' in recovery_data:
                    self.headers['sstt'] = urllib.parse.quote(recovery_data['sstt'])
                
                # Check recovery options
                if 'recoveryOptions' in recovery_data:
                    options = recovery_data['recoveryOptions']
                    logger.info(f"[{self.email}] Recovery options: {options}")
                    
                    if 'reset_password' in options:
                        return {
                            'status': 'unlocked',
                            'code': 'ok',
                            'message': 'Account is NOT locked - can reset password via security questions',
                            'action': 'Use flow_unlocked.py to change password',
                            'can_unlock': True,
                            'recovery_options': options
                        }
            except:
                pass
            
            # Try to continue to auth method selection
            select_resp = self.session.post(
                'https://iforgot.apple.com/recovery/options',
                headers=self.headers,
                json={"option": "reset_password"}
            )
            
            # Check for session timeout
            if select_resp.status_code == 302:
                location = select_resp.headers.get('Location', '')
                if 'session/timeout' in location:
                    return {
                        'status': 'temporary_lock',
                        'code': 'session/timeout',
                        'message': LOCK_STATUS['temporary_lock']['description'],
                        'action': LOCK_STATUS['temporary_lock']['action'],
                        'can_unlock': False
                    }
            
            # If we got here, account is likely unlocked
            return {
                'status': 'unlocked',
                'code': 'ok',
                'message': 'Account appears to be NOT locked',
                'action': 'Use flow_unlocked.py to change password',
                'can_unlock': True
            }
            
        except Exception as e:
            logger.error(f"[{self.email}] Deep check error: {e}")
            return {
                'status': 'unknown',
                'code': 'exception',
                'message': str(e),
                'action': 'Check logs',
                'can_unlock': False
            }


def check_account(account_data: str) -> dict:
    """Check a single account's lock status"""
    flow = LockedAccountFlow(account_data)
    return flow.check_lock_status()


def main():
    """Main entry point"""
    print(f"{Fore.CYAN}{'='*60}{Fore.RESET}")
    print(f"{Fore.CYAN}  Apple ID Lock Status Checker{Fore.RESET}")
    print(f"{Fore.CYAN}  Проверка статуса блокировки аккаунтов{Fore.RESET}")
    print(f"{Fore.CYAN}{'='*60}{Fore.RESET}\n")
    
    # Read accounts
    try:
        with open('files/Accounts.txt', 'r', encoding='utf-8') as f:
            accounts = [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}Error: files/Accounts.txt not found{Fore.RESET}")
        return
    
    if not accounts:
        print(f"{Fore.YELLOW}No accounts to process{Fore.RESET}")
        return
    
    print(f"Found {len(accounts)} account(s)\n")
    
    results = {
        'unlocked': [],
        'permanent_lock': [],
        'temporary_lock': [],
        'inactive': [],
        'invalid': [],
        'rate_limited': [],
        'unknown': []
    }
    
    for account in accounts:
        email = account.split(',')[0]
        print(f"{Fore.YELLOW}Checking: {email}{Fore.RESET}")
        
        result = check_account(account)
        status = result['status']
        
        # Color code output
        if status == 'unlocked':
            color = Fore.GREEN
            symbol = '✅'
        elif status == 'permanent_lock':
            color = Fore.RED
            symbol = '🔒'
        elif status == 'temporary_lock':
            color = Fore.YELLOW
            symbol = '🔐'
        elif status == 'inactive':
            color = Fore.MAGENTA
            symbol = '⏸️'
        elif status == 'invalid':
            color = Fore.RED
            symbol = '❌'
        elif status == 'rate_limited':
            color = Fore.YELLOW
            symbol = '⏳'
        else:
            color = Fore.WHITE
            symbol = '❓'
        
        print(f"{color}{symbol} Status: {result['message']}{Fore.RESET}")
        print(f"{color}   Action: {result['action']}{Fore.RESET}")
        print()
        
        # Categorize
        if status in results:
            results[status].append(account)
        else:
            results['unknown'].append(account)
    
    # Summary
    print(f"\n{Fore.CYAN}{'='*60}{Fore.RESET}")
    print(f"{Fore.CYAN}  SUMMARY / ИТОГИ{Fore.RESET}")
    print(f"{Fore.CYAN}{'='*60}{Fore.RESET}")
    
    print(f"\n{Fore.GREEN}✅ Unlocked (можно разблокировать): {len(results['unlocked'])}{Fore.RESET}")
    for acc in results['unlocked']:
        print(f"   - {acc.split(',')[0]}")
    
    print(f"\n{Fore.RED}🔒 Permanent Lock (полная блокировка): {len(results['permanent_lock'])}{Fore.RESET}")
    for acc in results['permanent_lock']:
        print(f"   - {acc.split(',')[0]}")
    
    print(f"\n{Fore.YELLOW}🔐 Temporary Lock (временная блокировка IP): {len(results['temporary_lock'])}{Fore.RESET}")
    for acc in results['temporary_lock']:
        print(f"   - {acc.split(',')[0]}")
    
    print(f"\n{Fore.MAGENTA}⏸️ Inactive (неактивные): {len(results['inactive'])}{Fore.RESET}")
    for acc in results['inactive']:
        print(f"   - {acc.split(',')[0]}")
    
    print(f"\n{Fore.RED}❌ Invalid (не существуют): {len(results['invalid'])}{Fore.RESET}")
    for acc in results['invalid']:
        print(f"   - {acc.split(',')[0]}")
    
    # Save results
    with open('files/check_unlocked.txt', 'w') as f:
        for acc in results['unlocked']:
            f.write(f"{acc}\n")
    
    with open('files/check_locked.txt', 'w') as f:
        for acc in results['permanent_lock']:
            f.write(f"{acc}\n")
    
    with open('files/check_temp_locked.txt', 'w') as f:
        for acc in results['temporary_lock']:
            f.write(f"{acc}\n")
    
    with open('files/check_inactive.txt', 'w') as f:
        for acc in results['inactive']:
            f.write(f"{acc}\n")
    
    print(f"\n{Fore.CYAN}Results saved to files/check_*.txt{Fore.RESET}")


if __name__ == '__main__':
    main()
