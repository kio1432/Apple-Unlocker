"""
Flow для смены пароля НЕЗАБЛОКИРОВАННОГО аккаунта Apple ID
Использует секретные вопросы для верификации

Этапы:
1. Загрузка iforgot.apple.com
2. Решение капчи
3. Верификация Apple ID
4. GET /recovery/options
5. POST /recovery/options (reset_password)
6. GET /password/authenticationmethod
7. POST /password/authenticationmethod (questions)
8. GET/POST birthday
9. GET/POST questions
10. Смена пароля
"""

import os
import time
import json
import random
import string
import logging
import urllib.parse
import tls_client
from colorama import Fore, init
from threading import Lock
from yescaptcha.task import ImageToTextTask
from yescaptcha.client import Client

init()
lock = Lock()

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('files/logs/flow_unlocked.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load settings
with open('files/settings.json', 'r') as f:
    settings = json.load(f)

# Security questions mapping
SECURITY_QUESTIONS = {
    # Chinese questions
    "你少年时代最好的朋友叫什么名字": 2,
    "你的第一个宠物叫什么名字": 2,
    "你学会做的第一道菜是什么": 2,
    "你第一次去电影院看的是哪一部电影": 2,
    "你第一次坐飞机是去哪里": 2,
    "你上小学时最喜欢的老师姓什么": 2,
    "你的理想工作是什么": 3,
    "你最喜欢的童年书籍是什么": 3,
    "你拥有的第一辆车是什么型号": 3,
    "你童年时代的绰号是什么": 3,
    "你在学生时代最喜欢哪个电影明星或角色": 3,
    "你在学生时代最喜欢哪个歌手或乐队": 3,
    "你的父母是在哪里认识的": 4,
    "你买的第一张专辑是什么": 4,
    "你最喜欢哪支球队": 4,
    "你是在哪里认识你配偶或另一半的": 4,
    "你在哪个城市遇见了你的配偶或重要的另一半": 4,
    "你儿时最好的朋友叫什么名字": 4,
    # English questions
    "best friend": 2,
    "first pet": 2,
    "first cook": 2,
    "first movie": 2,
    "first plane": 2,
    "favorite teacher": 2,
    "dream job": 3,
    "favorite book": 3,
    "first car": 3,
    "childhood nickname": 3,
    "favorite movie star": 3,
    "favorite singer": 3,
    "parents meet": 4,
    "first album": 4,
    "favorite team": 4,
    "meet spouse": 4,
    "childhood friend": 4,
}


class UnlockedAccountFlow:
    """Flow для смены пароля незаблокированного аккаунта"""
    
    def __init__(self, account_data: str):
        """
        account_data format: email,password,ans1,ans2,ans3,MM/DD/YYYY
        """
        self.data = account_data
        parts = account_data.split(',')
        self.email = parts[0].strip()
        self.password = parts[1].strip()
        self.answers = [parts[2].strip(), parts[3].strip(), parts[4].strip()]
        self.birthday = parts[5].strip()
        
        # Parse birthday
        bd_parts = self.birthday.split('/')
        self.birth_month = bd_parts[0]
        self.birth_day = bd_parts[1]
        self.birth_year = bd_parts[2]
        
        # Generate new password
        self.new_password = self._generate_password()
        
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
        self.captcha_token = None
    
    def _generate_password(self) -> str:
        """Generate a new password"""
        chars = random.choices(string.ascii_uppercase, k=2)
        chars += random.choices(string.ascii_lowercase, k=4)
        chars += random.choices(string.digits, k=3)
        random.shuffle(chars)
        return ''.join(chars)
    
    def _solve_captcha(self, image_base64: str) -> str:
        """Solve captcha using YesCaptcha"""
        try:
            api_key = settings.get('api_key') or settings.get('API_KEY', '')
            client = Client(client_key=api_key)
            task = ImageToTextTask(image_base64)
            job = client.create_task(task)
            return job.get_solution_text()
        except Exception as e:
            logger.error(f"[{self.email}] Captcha error: {e}")
            return None
    
    def _get_answer_index(self, question: str) -> int:
        """Get answer index based on question text"""
        question_lower = question.lower()
        for key, index in SECURITY_QUESTIONS.items():
            if key.lower() in question_lower:
                return index
        return 2  # Default to first answer
    
    def run(self) -> dict:
        """
        Execute the full password change flow
        Returns: {'success': bool, 'message': str, 'new_password': str}
        """
        start_time = time.time()
        logger.info(f"[{self.email}] Starting unlocked account flow...")
        logger.info(f"[{self.email}] New password will be: {self.new_password}")
        
        try:
            # STEP 1: Load initial page
            logger.info(f"[{self.email}] Step 1: Loading initial page...")
            resp = self.session.get(
                'https://iforgot.apple.com/password/verify/appleid',
                headers=self.headers
            )
            
            if resp.status_code != 200:
                return {'success': False, 'message': f'Initial page failed: {resp.status_code}', 'new_password': None}
            
            # Extract sstt token
            import re
            match = re.search(r'"sstt"\s*:\s*"([^"]+)"', resp.text)
            if match:
                self.sstt_token = urllib.parse.quote(match.group(1))
                self.headers['sstt'] = self.sstt_token
            
            # Update cookies
            self.headers['cookie'] = '; '.join([f"{k}={v}" for k, v in resp.cookies.items()])
            
            # STEP 2: Get and solve captcha
            logger.info(f"[{self.email}] Step 2: Getting captcha...")
            
            captcha_info = None
            for attempt in range(3):
                captcha_resp = self.session.get(
                    'https://iforgot.apple.com/captcha?captchaType=IMAGE',
                    headers=self.headers
                )
                
                if captcha_resp.status_code in [200, 401]:
                    try:
                        captcha_data = captcha_resp.json()
                        captcha_id = captcha_data.get('id', '')
                        captcha_token_resp = captcha_data.get('token', '')
                        
                        image_b64 = None
                        if 'captcha' in captcha_data:
                            image_b64 = captcha_data['captcha']
                        elif 'payload' in captcha_data and 'content' in captcha_data['payload']:
                            image_b64 = captcha_data['payload']['content']
                        
                        if image_b64:
                            if 'base64,' in image_b64:
                                image_b64 = image_b64.split('base64,')[1]
                            
                            captcha_answer = self._solve_captcha(image_b64)
                            if captcha_answer:
                                logger.info(f"[{self.email}] Captcha solved: {captcha_answer}")
                                captcha_info = {
                                    'id': captcha_id,
                                    'token': captcha_token_resp,
                                    'answer': captcha_answer
                                }
                                break
                    except Exception as e:
                        logger.error(f"[{self.email}] Captcha parse error: {e}")
                
                time.sleep(1)
            
            if not captcha_info:
                return {'success': False, 'message': 'Failed to solve captcha', 'new_password': None}
            
            # STEP 3: Verify Apple ID
            logger.info(f"[{self.email}] Step 3: Verifying Apple ID...")
            
            verify_data = {
                "id": self.email,
                "captcha": {
                    "id": captcha_info['id'],
                    "answer": captcha_info['answer'],
                    "token": captcha_info['token']
                }
            }
            
            for attempt in range(3):
                verify_resp = self.session.post(
                    'https://iforgot.apple.com/password/verify/appleid',
                    headers=self.headers,
                    json=verify_data
                )
                
                if 'captchaAnswer.Invalid' in verify_resp.text:
                    logger.warning(f"[{self.email}] Invalid captcha, retrying...")
                    # Get new captcha
                    captcha_resp = self.session.get(
                        'https://iforgot.apple.com/captcha?captchaType=IMAGE',
                        headers=self.headers
                    )
                    try:
                        captcha_data = captcha_resp.json()
                        if 'captcha' in captcha_data:
                            image_b64 = captcha_data['captcha'].replace('data:image/jpeg;base64,', '')
                            self.captcha_token = self._solve_captcha(image_b64)
                            verify_data['captcha']['token'] = self.captcha_token
                    except:
                        pass
                    continue
                elif verify_resp.status_code == 302:
                    break
                elif verify_resp.status_code == 503:
                    logger.warning(f"[{self.email}] Rate limited (503), waiting...")
                    time.sleep(5)
                    continue
                else:
                    # Check for errors
                    try:
                        error_data = verify_resp.json()
                        if 'service_errors' in error_data or 'serviceErrors' in error_data:
                            errors = error_data.get('service_errors') or error_data.get('serviceErrors', [])
                            for err in errors:
                                code = err.get('code', '')
                                if code == '-20101':
                                    return {'success': False, 'message': 'Invalid Apple ID', 'new_password': None}
                                elif code in ['-20209', '-20283']:
                                    return {'success': False, 'message': 'Account is LOCKED', 'new_password': None}
                                elif code in ['-20210', '-20751']:
                                    return {'success': False, 'message': 'Account is INACTIVE', 'new_password': None}
                    except:
                        pass
                    break
            
            if verify_resp.status_code != 302:
                return {'success': False, 'message': f'Apple ID verification failed: {verify_resp.status_code}', 'new_password': None}
            
            # STEP 4: Get recovery options
            logger.info(f"[{self.email}] Step 4: Getting recovery options...")
            
            location = verify_resp.headers.get('Location', '')
            recovery_resp = self.session.get(
                f'https://iforgot.apple.com{location}',
                headers=self.headers
            )
            
            if 'Sstt' in recovery_resp.headers:
                self.headers['sstt'] = recovery_resp.headers['Sstt']
            
            try:
                recovery_data = recovery_resp.json()
                if 'sstt' in recovery_data:
                    self.headers['sstt'] = urllib.parse.quote(recovery_data['sstt'])
            except:
                pass
            
            # STEP 5: Select reset_password option
            logger.info(f"[{self.email}] Step 5: Selecting reset_password option...")
            
            select_resp = self.session.post(
                'https://iforgot.apple.com/recovery/options',
                headers=self.headers,
                json={"option": "reset_password"}
            )
            
            if 'Sstt' in select_resp.headers:
                self.headers['sstt'] = select_resp.headers['Sstt']
            
            # STEP 6: Get authentication method page
            logger.info(f"[{self.email}] Step 6: Getting authentication method page...")
            
            if select_resp.status_code == 302 and 'Location' in select_resp.headers:
                auth_get_resp = self.session.get(
                    f'https://iforgot.apple.com{select_resp.headers["Location"]}',
                    headers=self.headers
                )
            else:
                auth_get_resp = self.session.get(
                    'https://iforgot.apple.com/password/authenticationmethod',
                    headers=self.headers
                )
            
            if 'Sstt' in auth_get_resp.headers:
                self.headers['sstt'] = auth_get_resp.headers['Sstt']
            
            try:
                auth_data = auth_get_resp.json()
                if 'sstt' in auth_data:
                    self.headers['sstt'] = urllib.parse.quote(auth_data['sstt'])
            except:
                pass
            
            # STEP 7: Select questions authentication method
            logger.info(f"[{self.email}] Step 7: Selecting questions auth method...")
            
            auth_post_resp = self.session.post(
                'https://iforgot.apple.com/password/authenticationmethod',
                headers=self.headers,
                json={"type": "questions"}
            )
            
            if 'Sstt' in auth_post_resp.headers:
                self.headers['sstt'] = auth_post_resp.headers['Sstt']
            
            # STEP 8: Birthday verification
            logger.info(f"[{self.email}] Step 8: Birthday verification...")
            
            if auth_post_resp.status_code == 302 and 'Location' in auth_post_resp.headers:
                birthday_get_resp = self.session.get(
                    f'https://iforgot.apple.com{auth_post_resp.headers["Location"]}',
                    headers=self.headers
                )
            else:
                birthday_get_resp = self.session.get(
                    'https://iforgot.apple.com/password/verify/birthday',
                    headers=self.headers
                )
            
            if 'Sstt' in birthday_get_resp.headers:
                self.headers['sstt'] = birthday_get_resp.headers['Sstt']
            else:
                # Check for session timeout
                if 'session/timeout' in str(birthday_get_resp.url) or 'session/timeout' in birthday_get_resp.headers.get('Location', ''):
                    return {'success': False, 'message': 'Session timeout - possible IP block', 'new_password': None}
            
            # POST birthday
            birthday_data = {
                "monthOfYear": self.birth_month,
                "dayOfMonth": self.birth_day,
                "year": self.birth_year
            }
            
            birthday_post_resp = self.session.post(
                'https://iforgot.apple.com/password/verify/birthday',
                headers=self.headers,
                json=birthday_data
            )
            
            if 'Sstt' in birthday_post_resp.headers:
                self.headers['sstt'] = birthday_post_resp.headers['Sstt']
            
            # STEP 9: Security questions
            logger.info(f"[{self.email}] Step 9: Answering security questions...")
            
            if birthday_post_resp.status_code == 302 and 'Location' in birthday_post_resp.headers:
                questions_get_resp = self.session.get(
                    f'https://iforgot.apple.com{birthday_post_resp.headers["Location"]}',
                    headers=self.headers
                )
            else:
                questions_get_resp = self.session.get(
                    'https://iforgot.apple.com/password/verify/questions',
                    headers=self.headers
                )
            
            if 'Sstt' in questions_get_resp.headers:
                self.headers['sstt'] = questions_get_resp.headers['Sstt']
            
            try:
                questions_data = questions_get_resp.json()
            except:
                return {'success': False, 'message': 'Failed to get questions', 'new_password': None}
            
            if 'questions' not in questions_data:
                return {'success': False, 'message': 'No questions in response', 'new_password': None}
            
            questions = questions_data['questions']
            logger.info(f"[{self.email}] Got {len(questions)} questions")
            
            # Build questions payload (format from old working code)
            questions_payload = {"questions": []}
            
            for q in questions:
                q_id = q['id']
                q_text = q['question']
                q_num = q['number']
                
                answer_idx = self._get_answer_index(q_text)
                answer = self.answers[answer_idx - 2]  # answers array is 0-indexed, indices are 2,3,4
                
                logger.info(f"[{self.email}] Q{q_num}: '{q_text[:30]}...' -> Answer: '{answer}'")
                
                questions_payload['questions'].append({
                    "question": q_text,
                    "answer": answer,
                    "id": q_id,
                    "number": q_num
                })
            
            # POST questions
            questions_post_resp = self.session.post(
                'https://iforgot.apple.com/password/verify/questions',
                headers=self.headers,
                json=questions_payload
            )
            
            if questions_post_resp.status_code != 302:
                try:
                    error_data = questions_post_resp.json()
                    if 'service_errors' in error_data:
                        return {'success': False, 'message': f'Wrong answers: {error_data}', 'new_password': None}
                except:
                    pass
                return {'success': False, 'message': f'Questions verification failed: {questions_post_resp.status_code}', 'new_password': None}
            
            if 'Sstt' in questions_post_resp.headers:
                self.headers['sstt'] = questions_post_resp.headers['Sstt']
            
            # STEP 10: Reset password
            logger.info(f"[{self.email}] Step 10: Resetting password...")
            
            reset_get_resp = self.session.get(
                f'https://iforgot.apple.com{questions_post_resp.headers["Location"]}',
                headers=self.headers
            )
            
            if 'Sstt' in reset_get_resp.headers:
                self.headers['sstt'] = reset_get_resp.headers['Sstt']
            
            reset_data = {
                "password": self.new_password,
                "confirmPassword": self.new_password
            }
            
            reset_post_resp = self.session.post(
                'https://iforgot.apple.com/password/reset',
                headers=self.headers,
                json=reset_data
            )
            
            elapsed = time.time() - start_time
            
            if reset_post_resp.status_code in [200, 260, 302]:
                logger.info(f"[{self.email}] SUCCESS! Password changed in {elapsed:.1f}s")
                return {
                    'success': True,
                    'message': f'Password changed successfully in {elapsed:.1f}s',
                    'new_password': self.new_password
                }
            else:
                return {
                    'success': False,
                    'message': f'Password reset failed: {reset_post_resp.status_code}',
                    'new_password': None
                }
                
        except Exception as e:
            logger.error(f"[{self.email}] Error: {e}")
            return {'success': False, 'message': str(e), 'new_password': None}


def process_account(account_data: str) -> dict:
    """Process a single account"""
    flow = UnlockedAccountFlow(account_data)
    return flow.run()


def main():
    """Main entry point"""
    print(f"{Fore.CYAN}[+] Unlocked Account Password Change Flow{Fore.RESET}")
    print(f"{Fore.CYAN}[+] For accounts with security questions{Fore.RESET}\n")
    
    # Read accounts from Accounts.txt
    try:
        with open('files/Accounts.txt', 'r', encoding='utf-8') as f:
            accounts = [line.strip() for line in f.readlines() if line.strip()]
        print(f"Reading from: files/Accounts.txt")
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
        
        result = process_account(account)
        
        if result['success']:
            print(f"{Fore.GREEN}[SUCCESS] {email} -> New password: {result['new_password']}{Fore.RESET}")
            new_account = account.replace(account.split(',')[1], result['new_password'])
            with lock:
                from datetime import datetime
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                # Write to Success.txt
                with open('files/Success.txt', 'a+') as f:
                    f.write(f"{new_account} | {timestamp}\n")
                
                # Update Accounts.txt - replace old account with new password
                try:
                    with open('files/Accounts.txt', 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                    with open('files/Accounts.txt', 'w', encoding='utf-8') as f:
                        for line in lines:
                            if line.strip() == account:
                                f.write(f"{new_account}\n")
                            else:
                                f.write(line)
                except Exception as e:
                    logger.error(f"Failed to update Accounts.txt: {e}")
        else:
            print(f"{Fore.RED}[FAILED] {email} -> {result['message']}{Fore.RESET}")
            with lock:
                from datetime import datetime
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                with open('files/error.txt', 'a+') as f:
                    f.write(f"{account} - {result['message']} | {timestamp}\n")
        
        print()


if __name__ == '__main__':
    main()