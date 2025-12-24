"""
Flow для смены пароля через SRP авторизацию + idmsa API

СТАТУС: В РАЗРАБОТКЕ (НЕ ГОТОВ)

Исследование показало:
- SRP авторизация работает (409 = valid with security questions)
- Security questions можно получить через /verify/securityquestion
- Ответы отправляются через /verify/questions
- После repair/complete получаем myacinfo cookie
- НО: для смены пароля Apple требует повторную авторизацию через SQ (step-up auth)
- Ответы на SQ для step-up возвращают 412 (требуется fingerprint)

Найденный endpoint для смены пароля:
- PUT https://appleid.apple.com/account/manage/security/password
- Payload: {"currentPassword": "...", "newPassword": "..."}

Проблема: требуется корректный fingerprint X-Apple-I-FD-Client-Info
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
from apple_fingerprint import generate_fingerprint

init()
lock = Lock()

# Logging setup
os.makedirs('files/logs', exist_ok=True)
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


class SrpPassword:
    """Custom password class for Apple's SRP implementation"""
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


class LoginFlow:
    """Flow для смены пароля через SRP авторизацию"""
    
    CLIENT_ID = 'af1139274f266b22b68c2a3e7ad932cb3c0bbe854e13a79af78dcc73136882c3'
    
    def __init__(self, account_data: str):
        parts = account_data.split(',')
        self.email = parts[0].strip()
        self.password = parts[1].strip()
        self.answers = [parts[2].strip(), parts[3].strip(), parts[4].strip()]
        self.birthday = parts[5].strip() if len(parts) > 5 else ''
        
        # Question ID to answer mapping
        self.q_answers = {
            130: self.answers[0].lower(),  # childhood friend
            136: self.answers[1].lower(),  # dream job
            142: self.answers[2].lower(),  # where parents met
        }
        
        self.new_password = self._generate_password()
        self.session = requests.Session()
        
        # Generate fingerprint
        self.fd_client_info = generate_fingerprint(language='ru-RU', timezone='GMT+03:00')
        
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/plain, */*',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Origin': 'https://idmsa.apple.com',
            'Referer': 'https://idmsa.apple.com/',
            'X-Apple-Widget-Key': self.CLIENT_ID,
            'X-Apple-OAuth-Client-Id': self.CLIENT_ID,
            'X-Apple-OAuth-Client-Type': 'firstPartyAuth',
            'X-Apple-OAuth-Redirect-URI': 'https://account.apple.com',
            'X-Apple-OAuth-Response-Type': 'code',
            'X-Apple-OAuth-Response-Mode': 'web_message',
            'X-Apple-Domain-Id': '11',
            'X-Apple-I-FD-Client-Info': self.fd_client_info,
        }
    
    def _generate_password(self) -> str:
        chars = random.choices(string.ascii_uppercase, k=2)
        chars += random.choices(string.ascii_lowercase, k=4)
        chars += random.choices(string.digits, k=3)
        random.shuffle(chars)
        return ''.join(chars)
    
    def _b64_encode(self, data: bytes) -> str:
        return base64.b64encode(data).decode('utf-8')
    
    def _update_headers(self, resp):
        for h in ['scnt', 'X-Apple-Auth-Attributes', 'X-Apple-ID-Session-Id']:
            if h in resp.headers:
                self.headers[h] = resp.headers[h]
    
    def _answer_sq(self, questions: list) -> dict:
        payload = {'questions': []}
        for q in questions:
            ans = self.q_answers.get(q['id'], self.answers[0].lower())
            logger.info(f"[{self.email}] Q{q['number']} (id={q['id']}): {ans}")
            payload['questions'].append({
                'question': q['question'],
                'answer': ans,
                'id': q['id'],
                'number': q['number']
            })
        return payload
    
    def run(self) -> dict:
        """Execute the SRP login flow"""
        logger.info(f"[{self.email}] Starting SRP login flow...")
        
        try:
            # Step 1: SRP Init
            logger.info(f"[{self.email}] Step 1: SRP Init")
            srp_password = SrpPassword(self.password)
            srp.rfc5054_enable()
            srp.no_username_in_x()
            usr = srp.User(self.email, srp_password, hash_alg=srp.SHA256, ng_type=srp.NG_2048)
            uname, A = usr.start_authentication()
            
            init_resp = self.session.post(
                'https://idmsa.apple.com/appleauth/auth/signin/init',
                json={'a': self._b64_encode(A), 'accountName': uname, 'protocols': ['s2k', 's2k_fo']},
                headers=self.headers
            )
            
            if init_resp.status_code != 200:
                return {'success': False, 'message': f'SRP init failed: {init_resp.status_code}', 'new_password': None}
            
            body = init_resp.json()
            salt = base64.b64decode(body['salt'])
            b = base64.b64decode(body['b'])
            srp_password.set_encrypt_info(salt, body['iteration'], 32)
            self._update_headers(init_resp)
            
            time.sleep(1)
            
            # Step 2: SRP Complete
            logger.info(f"[{self.email}] Step 2: SRP Complete")
            m1 = usr.process_challenge(salt, b)
            m2 = usr.H_AMK
            
            complete_resp = self.session.post(
                'https://idmsa.apple.com/appleauth/auth/signin/complete',
                params={'isRememberMeEnabled': 'true'},
                json={'accountName': uname, 'c': body['c'], 'm1': self._b64_encode(m1), 'm2': self._b64_encode(m2), 'rememberMe': False},
                headers=self.headers
            )
            
            logger.info(f"[{self.email}] SRP Complete: {complete_resp.status_code}")
            self._update_headers(complete_resp)
            
            if complete_resp.status_code == 401:
                return {'success': False, 'message': 'Invalid password', 'new_password': None}
            
            if complete_resp.status_code not in [200, 409]:
                return {'success': False, 'message': f'SRP complete failed: {complete_resp.status_code}', 'new_password': None}
            
            time.sleep(1)
            
            # Step 3: Get Security Questions
            logger.info(f"[{self.email}] Step 3: Get Security Questions")
            sq_resp = self.session.get(
                'https://idmsa.apple.com/appleauth/auth/verify/securityquestion',
                headers=self.headers
            )
            
            logger.info(f"[{self.email}] GET SQ: {sq_resp.status_code}")
            self._update_headers(sq_resp)
            
            if sq_resp.status_code != 200:
                return {'success': False, 'message': f'Failed to get SQ: {sq_resp.status_code}', 'new_password': None}
            
            questions = sq_resp.json().get('securityQuestions', {}).get('questions', [])
            logger.info(f"[{self.email}] Got {len(questions)} questions")
            
            time.sleep(1)
            
            # Step 4: Answer Security Questions
            logger.info(f"[{self.email}] Step 4: Answer Security Questions")
            ans_resp = self.session.post(
                'https://idmsa.apple.com/appleauth/auth/verify/questions',
                headers=self.headers,
                json=self._answer_sq(questions)
            )
            
            logger.info(f"[{self.email}] Answer SQ: {ans_resp.status_code}")
            self._update_headers(ans_resp)
            
            time.sleep(1)
            
            # Step 5: Repair
            logger.info(f"[{self.email}] Step 5: Repair")
            repair_resp = self.session.post(
                'https://idmsa.apple.com/appleauth/auth/repair/complete',
                headers=self.headers,
                json={}
            )
            
            logger.info(f"[{self.email}] Repair: {repair_resp.status_code}")
            self._update_headers(repair_resp)
            
            if 'myacinfo' not in self.session.cookies:
                return {'success': False, 'message': 'No session cookie', 'new_password': None}
            
            logger.info(f"[{self.email}] Session established!")
            
            time.sleep(1)
            
            # Step 6: Try password change via appleid.apple.com
            logger.info(f"[{self.email}] Step 6: Password Change")
            
            change_headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'User-Agent': self.headers['User-Agent'],
                'Origin': 'https://appleid.apple.com',
                'Referer': 'https://appleid.apple.com/account/manage/section/security',
            }
            
            change_resp = self.session.put(
                'https://appleid.apple.com/account/manage/security/password',
                headers=change_headers,
                json={'currentPassword': self.password, 'newPassword': self.new_password}
            )
            
            logger.info(f"[{self.email}] Password change: {change_resp.status_code}")
            
            if change_resp.status_code == 200:
                return {
                    'success': True,
                    'message': 'Password changed successfully',
                    'new_password': self.new_password
                }
            else:
                return {
                    'success': False,
                    'message': f'Password change failed: {change_resp.status_code} - {change_resp.text[:200]}',
                    'new_password': None
                }
                
        except Exception as e:
            logger.error(f"[{self.email}] Error: {e}")
            return {'success': False, 'message': str(e), 'new_password': None}


def main():
    print(f"{Fore.CYAN}[+] SRP Login Password Change Flow{Fore.RESET}")
    print(f"{Fore.YELLOW}[!] STATUS: IN DEVELOPMENT{Fore.RESET}\n")
    
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
    
    for account in accounts:
        email = account.split(',')[0]
        print(f"{Fore.YELLOW}Processing: {email}{Fore.RESET}")
        
        flow = LoginFlow(account)
        result = flow.run()
        
        if result['success']:
            print(f"{Fore.GREEN}[SUCCESS] {email} -> {result['new_password']}{Fore.RESET}")
        else:
            print(f"{Fore.RED}[FAILED] {email} -> {result['message']}{Fore.RESET}")
        
        print()


if __name__ == '__main__':
    main()
