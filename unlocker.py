import os
import time
import json
import random
import hashlib
import logging
import string
import tls_client
import urllib.parse
from colorama import Fore
from threading import Lock
from yescaptcha.task import ImageToTextTask
from yescaptcha.client import Client
import concurrent.futures
from evpn import ExpressVpnApi

lock = Lock()
# Enhanced logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('files/debug.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__) 

with open("files/settings.json")as f:
    settings = json.load(f)

def generate_password(email, old_password=None):
    """
    Generate simple, easy-to-type passwords like:
    AAAaaab82, BBBccc123, XXXyyy456
    
    Requirements:
    - Minimum 8 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter  
    - At least 1 digit
    - Does not contain email/Apple ID
    - Does not match old password
    """
    # Simple patterns with repeating characters
    patterns = [
        # AAAbbb82
        lambda: random.choice('ABCDEFGHJKLMNPQRSTUVWXYZ') * 3 + random.choice('abcdefghjkmnpqrstuvwxyz') * 3 + str(random.randint(10, 99)),
        # AAAbbb123
        lambda: random.choice('ABCDEFGHJKLMNPQRSTUVWXYZ') * 3 + random.choice('abcdefghjkmnpqrstuvwxyz') * 3 + str(random.randint(100, 999)),
        # AAbbCC12
        lambda: random.choice('ABCDEFGHJKLMNPQRSTUVWXYZ') * 2 + random.choice('abcdefghjkmnpqrstuvwxyz') * 2 + random.choice('ABCDEFGHJKLMNPQRSTUVWXYZ') * 2 + str(random.randint(10, 99)),
        # Abbbb1X23
        lambda: random.choice('ABCDEFGHJKLMNPQRSTUVWXYZ') + random.choice('abcdefghjkmnpqrstuvwxyz') * 4 + random.choice('ABCDEFGHJKLMNPQRSTUVWXYZ') + str(random.randint(100, 999)),
    ]
    
    email_parts = email.lower().split('@')[0]
    
    for _ in range(50):
        password = random.choice(patterns)()
        
        if email_parts in password.lower():
            continue
        if old_password and password == old_password:
            continue
            
        return password
    
    return f"AAAbbb{random.randint(100, 999)}"

def save_generated_password(email, new_password):
    """Save generated password to passwords log file"""
    with lock:
        with open("files/passwords.txt", "a+", encoding='utf-8') as f:
            f.write(f"{email},{new_password}\n")

def remove_line_containing_text(file_path, target_text):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()

        updated_lines = [line for line in lines if target_text not in line]

        with open(file_path, 'w', encoding='utf-8') as file:
            file.writelines(updated_lines)

    except FileNotFoundError:
        print("No Such File dict")
    except Exception as e:
        print(f"An ERROR : {e}")

# Security questions mapping - expanded to cover more variations
qus = {
    # Chinese versions of security questions
    "你少年时代最好的朋友叫什么名字": 2,
    "你少年时代最好的朋友叫什么名字？": 2,
    "你的理想工作是什么": 3,
    "你的理想工作是什么？": 3,
    "你的父母是在哪里认识的": 4,
    "你的父母是在哪里认识的？": 4,
    
    # English versions of security questions
    "the name of a childhood friend": 2,
    "What is the name of a childhood friend?": 2,
    "What was the name of your childhood friend?": 2,
    "What is the name of your childhood friend?": 2,
    "Name of a childhood friend": 2,
    
    "dream job": 3,
    "What is your dream job?": 3,
    "What was your dream job?": 3,
    "What is your ideal job?": 3,
    "What was your ideal job?": 3,
    "Dream job": 3,
    "Ideal job": 3,
    
    "where the parents met": 4,
    "Where did your parents meet?": 4,
    "Where did your parents first meet?": 4,
    "Where your parents met": 4,
    "Where parents met": 4,
    
    # Additional common security questions (adjust indices as needed)
    "What was your first pet's name?": 5,
    "What is your first pet's name?": 5,
    "First pet's name": 5,
    "你的第一只宠物叫什么名字": 5,
    "你的第一只宠物叫什么名字？": 5,
    
    "What was the name of your first school?": 6,
    "What is the name of your first school?": 6,
    "First school name": 6,
    "你第一所学校的名字是什么": 6,
    "你第一所学校的名字是什么？": 6,
    
    "What city were you born in?": 7,
    "What was your birth city?": 7,
    "Birth city": 7,
    "你出生在哪个城市": 7,
    "你出生在哪个城市？": 7
}


# Apple ID Unlocker Script Started
print(f"{Fore.GREEN}[+] Apple ID Unlocker Started{Fore.RESET}")
class unlocker():

    def __init__(self) -> None:
        self.max_retries = 3  # Maximum retry attempts for session timeout
        
    def unlock(self, data_email, retry_count=0):
        try:


            start = time.time()
            self.key =  settings['API_KEY']
            self.data_email =data_email
            self.email = data_email.split(',')[0]
            self.password = data_email.split(',')[1]
            # Generate unique password or use from settings
            if settings.get('auto_generate_password', False):
                self.new_password = generate_password(self.email, self.password)
                logger.info(f"[{self.email}] Generated new password: {self.new_password}")
            else:
                self.new_password = settings['new_password']


            """ SETUP """
            self.session =tls_client.Session(random_tls_extension_order=True , client_identifier="chrome_128")

            self.headers = {
                "accept-language": "en-US,en;q=0.9,ar;q=0.8",
                "cache-control": "no-cache",
                "content-type": "application/json",
                "pragma": "no-cache",
                "sec-ch-ua": "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "\"Windows\"",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            }

            """ * Get sstt * """

            sendForget = self.session.get('https://iforgot.apple.com/password/verify/appleid',headers=self.headers)
            self.sstt = urllib.parse.quote(sendForget.text.split('"https://iforgot.apple.com","contextUrl":"/","sstt":"')[1].split('","captchaEnabled":true,')[0])


            """ * Set Headers * """

            self.headers['cookie'] = '; '.join([f"{name}={value}" for name, value in sendForget.cookies.items()])
            self.headers['sstt'] = self.sstt
            self.headers['accept']= "application/json, text/javascript, */*; q=0.01"
            self.headers['x-requested-with'] = 'XMLHttpRequests'
            self.headers['x-apple-i-fd-client-info'] = '{"U":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36","L":"en-US","Z":"GMT+02:00","V":"1.1","F":"sla44j1e3NlY5BNlY5BSs5uQ084akLK77J_v495JppM.S9RdPQSzOy_Aw7UTlWY5Ly.eaB0Tf0IY69WJQStMw8btHz3Y25BNlY5cklY5BqNAE.lTjV.6KH"}'


            """ * Get Captcha INFO * """
            while True:
                sendCaptcha = self.session.get('https://iforgot.apple.com/captcha?captchaType=IMAGE',headers=self.headers)
                self.token = sendCaptcha.json()['token']
                self.capImg = sendCaptcha.json()['payload']['content']
                self.id = sendCaptcha.json()['id']


                """ * CAP SOLVE * """
                client = Client(client_key=self.key)
                task  = ImageToTextTask(self.capImg)
                job = client.create_task(task)

                """ * Start unlock * """

                data ={
                    "id": self.email,
                    "captcha": {
                        "id": self.id,
                        "answer":job.get_solution_text(),
                        "token":self.token
                    }
                }   

                sendAppleid = self.session.post('https://iforgot.apple.com/password/verify/appleid',headers=self.headers,json=data)

                if 'captchaAnswer.Invalid' in sendAppleid.text:
                    pass
                elif sendAppleid.status_code == 503:
                    # Check if VPN is enabled in settings before attempting to change VPN
                    if settings.get('vpn_enabled', True):  # Default to True if not specified
                        with ExpressVpnApi() as api:
                            ran = random.choice([84,3,166,19,1,202,2,165,18,172,161,9,95,3,74,3,70,204,94,71,207,79,45,169,178,15,90,5,153,8,103,150,182,29])
                            api.connect(ran)
                        print(f"{Fore.GREEN} [ + ] VPN was Changed Successfuly===> retrying ")
                        time.sleep(10)
                    else:
                        print(f"{Fore.YELLOW} [ ! ] VPN is disabled in settings - skipping VPN change")
                        time.sleep(5)  # Still add some delay
                    pass

                else:
                    break
            if sendAppleid.status_code == 302:
                """ * Get Recovery Options * """
                logger.info(f"[{self.email}] Step: Getting recovery options...")
                
                sendRecoveryOptions = self.session.get(f'https://iforgot.apple.com{sendAppleid.headers["Location"]}',headers=self.headers)
                
                # Update sstt from response
                if 'Sstt' in sendRecoveryOptions.headers:
                    self.headers['sstt'] = sendRecoveryOptions.headers['Sstt']
                    logger.info(f"[{self.email}] Got Sstt from recovery options")
                
                # Also check JSON response for sstt
                try:
                    recovery_data = sendRecoveryOptions.json()
                    if 'sstt' in recovery_data:
                        self.headers['sstt'] = urllib.parse.quote(recovery_data['sstt'])
                        logger.info(f"[{self.email}] Got Sstt from recovery options JSON")
                except:
                    pass
                
                """ * Select reset_password option * """
                logger.info(f"[{self.email}] Step: Selecting reset_password option...")
                
                sendSelectOption = self.session.post('https://iforgot.apple.com/recovery/options',headers=self.headers,json={"option": "reset_password"})
                
                if 'Sstt' in sendSelectOption.headers:
                    self.headers['sstt'] = sendSelectOption.headers['Sstt']
                    logger.info(f"[{self.email}] Got Sstt from select option")
                
                # Follow redirect to authenticationmethod
                if sendSelectOption.status_code == 302 and 'Location' in sendSelectOption.headers:
                    logger.info(f"[{self.email}] Step: Getting authentication method page...")
                    
                    sendAuthMethodGET = self.session.get(f'https://iforgot.apple.com{sendSelectOption.headers["Location"]}',headers=self.headers)
                    
                    if 'Sstt' in sendAuthMethodGET.headers:
                        self.headers['sstt'] = sendAuthMethodGET.headers['Sstt']
                        logger.info(f"[{self.email}] Got Sstt from auth method GET")
                    
                    # Extract sstt from JSON if present
                    try:
                        auth_data = sendAuthMethodGET.json()
                        if 'sstt' in auth_data:
                            self.headers['sstt'] = urllib.parse.quote(auth_data['sstt'])
                            logger.info(f"[{self.email}] Got Sstt from auth method JSON")
                    except:
                        pass
                else:
                    # If no redirect, try to get auth method page directly
                    logger.info(f"[{self.email}] No redirect from select option (status: {sendSelectOption.status_code}), trying direct GET...")
                    sendAuthMethodGET = self.session.get('https://iforgot.apple.com/password/authenticationmethod',headers=self.headers)
                    
                    if 'Sstt' in sendAuthMethodGET.headers:
                        self.headers['sstt'] = sendAuthMethodGET.headers['Sstt']
                        logger.info(f"[{self.email}] Got Sstt from direct auth method GET")
                    
                    try:
                        auth_data = sendAuthMethodGET.json()
                        if 'sstt' in auth_data:
                            self.headers['sstt'] = urllib.parse.quote(auth_data['sstt'])
                            logger.info(f"[{self.email}] Got Sstt from direct auth method JSON")
                    except:
                        pass

                """ * Send authenticationmethod - select questions * """
                logger.info(f"[{self.email}] Step: Selecting questions auth method...")

                sendAuthenticationmethod = self.session.post('https://iforgot.apple.com/password/authenticationmethod',headers=self.headers,json={"type":"questions"})
                
                if 'Sstt' in sendAuthenticationmethod.headers:
                    self.headers['sstt'] = sendAuthenticationmethod.headers['Sstt']
                    logger.info(f"[{self.email}] Got Sstt from auth method POST")

                """ * Send Birthday * """
                logger.info(f"[{self.email}] Step: Getting birthday page...")
                
                # Follow redirect from auth method if present
                if sendAuthenticationmethod.status_code == 302 and 'Location' in sendAuthenticationmethod.headers:
                    sendBirthdayGET = self.session.get(f'https://iforgot.apple.com{sendAuthenticationmethod.headers["Location"]}',headers=self.headers)
                else:
                    sendBirthdayGET = self.session.get('https://iforgot.apple.com/password/verify/birthday',headers=self.headers)
                
                # Check if Sstt header exists
                if 'Sstt' in sendBirthdayGET.headers:
                    self.headers['sstt'] = sendBirthdayGET.headers['Sstt']
                    logger.info(f"[{self.email}] Got Sstt token from birthday GET")
                else:
                    logger.error(f"[{self.email}] No Sstt header in birthday GET response")
                    logger.error(f"[{self.email}] Available headers: {list(sendBirthdayGET.headers.keys())}")
                    print(f"{Fore.RED}ERROR  'Sstt' - Missing Sstt header in birthday response{Fore.RESET}")
                    print(f"{Fore.RED} [ + ] {self.email} ==> ERROR While unlock ==>{Fore.RESET}")
                    with lock:
                        with open("files/error.txt","a+")as f :
                            f.write(f'{self.data_email} - Missing Sstt header in birthday response\n')
                    return

                """ * sendBirthdayPOST * """
                data = {
                    "monthOfYear":self.data_email.split(',')[5].split('/')[0],
                    "dayOfMonth":self.data_email.split(',')[5].split('/')[1],
                    "year":self.data_email.split(',')[5].split('/')[2]
                }
                sendBirthdayPOST = self.session.post('https://iforgot.apple.com/password/verify/birthday',headers=self.headers,json=data)
                print(sendBirthdayPOST.text)

                if sendBirthdayPOST.status_code == 410:
                    print(f"{Fore.RED} [ + ] {self.email} ==> ERROR While unlock ==> TO many Attempts ERORR")
                    with lock:
                        with open("files/error.txt","a+")as f :
                            f.write(f'{self.data_email}\n')     
                    return
                    
                # Check if Sstt header exists in birthday POST response (optional)
                if 'Sstt' in sendBirthdayPOST.headers:
                    self.headers['sstt'] = sendBirthdayPOST.headers['Sstt']
                    logger.info(f"[{self.email}] Got Sstt token from birthday POST")
                else:
                    logger.warning(f"[{self.email}] No Sstt header in birthday POST response - continuing with existing token")
                    logger.info(f"[{self.email}] Available headers: {list(sendBirthdayPOST.headers.keys())}")
                    print(f"{Fore.YELLOW}[WARNING] {self.email} - No Sstt in birthday POST, using existing token{Fore.RESET}")
                    # Continue execution - we may still have a valid Sstt from previous request
        
                """ * Get Questions * """
                sendQuestionsGET = self.session.get(f'https://iforgot.apple.com{sendBirthdayPOST.headers["Location"]}',headers=self.headers)
                
                # Check if Sstt header exists in questions GET response (optional)
                if 'Sstt' in sendQuestionsGET.headers:
                    self.headers['sstt'] = sendQuestionsGET.headers['Sstt']
                    logger.info(f"[{self.email}] Got Sstt token from questions GET")
                else:
                    logger.warning(f"[{self.email}] No Sstt header in questions GET response - continuing with existing token")
                    logger.info(f"[{self.email}] Available headers: {list(sendQuestionsGET.headers.keys())}")
                    print(f"{Fore.YELLOW}[WARNING] {self.email} - No Sstt in questions GET, using existing token{Fore.RESET}")
                    # Continue execution - we may still have a valid Sstt from previous request


                """ * Set Payload * """
                
                # Check if response contains questions
                try:
                    response_json = sendQuestionsGET.json()
                    logger.info(f"[{self.email}] Questions response: {response_json}")
                    
                    if 'questions' not in response_json:
                        logger.error(f"[{self.email}] No 'questions' key in response: {response_json}")
                        logger.error(f"[{self.email}] Questions GET status code: {sendQuestionsGET.status_code}")
                        logger.error(f"[{self.email}] Questions GET URL: {sendQuestionsGET.url}")
                        
                        # Check if it's an empty response or error response
                        if response_json == {}:
                            # Check if it's a session timeout
                            if 'session/timeout' in str(sendQuestionsGET.url):
                                logger.error(f"[{self.email}] SESSION TIMEOUT DETECTED (attempt {retry_count + 1}/{self.max_retries})")
                                logger.error(f"[{self.email}] Apple session expired before reaching security questions")
                                
                                # Retry logic
                                if retry_count < self.max_retries - 1:
                                    wait_time = (retry_count + 1) * 10  # 10s, 20s, 30s
                                    print(f"{Fore.YELLOW}[RETRY] Session timeout - waiting {wait_time}s before retry {retry_count + 2}/{self.max_retries}{Fore.RESET}")
                                    time.sleep(wait_time)
                                    return self.unlock(data_email, retry_count + 1)  # Recursive retry
                                
                                print(f"{Fore.RED}ERROR - Session timeout (all {self.max_retries} attempts failed){Fore.RESET}")
                                print(f"{Fore.YELLOW}Suggestion: This is likely due to Apple's security measures{Fore.RESET}")
                                print(f"{Fore.YELLOW}Try again later or check account status{Fore.RESET}")
                            else:
                                logger.error(f"[{self.email}] Empty JSON response - possible causes:")
                                logger.error(f"[{self.email}] 1. Incorrect birthday data")
                                logger.error(f"[{self.email}] 2. Account locked/blocked")
                                logger.error(f"[{self.email}] 3. Too many attempts")
                                logger.error(f"[{self.email}] 4. Apple API changes")
                                print(f"{Fore.RED}ERROR - Empty questions response (possible birthday/account issue){Fore.RESET}")
                                print(f"{Fore.YELLOW}Suggestion: Check birthday format in Accounts.txt (MM/DD/YY){Fore.RESET}")
                        else:
                            print(f"{Fore.RED}ERROR  'questions'{Fore.RESET}")
                            
                        print(f"{Fore.RED} [ + ] {self.email} ==> ERROR While unlock ==>{Fore.RESET}")
                        with lock:
                            with open("files/error.txt","a+")as f :
                                f.write(f'{self.data_email} - No questions in response (empty JSON)\n')
                        return
                    
                    if len(response_json['questions']) < 2:
                        logger.error(f"[{self.email}] Not enough questions in response: {len(response_json['questions'])}")
                        print(f"{Fore.RED}[ERROR] Not enough questions received{Fore.RESET}")
                        with lock:
                            with open("files/error.txt","a+")as f :
                                f.write(f'{self.data_email} - Not enough questions\n')
                        return
                        
                    question1 = response_json['questions'][0]['question']
                    question2 = response_json['questions'][1]['question']
                    number1 = response_json['questions'][0]['number']
                    number2 = response_json['questions'][1]['number']
                    qu_id1 = response_json['questions'][0]['id']
                    qu_id2 = response_json['questions'][1]['id']
                    
                except (KeyError, IndexError, ValueError) as e:
                    logger.error(f"[{self.email}] Error parsing questions response: {e}")
                    logger.error(f"[{self.email}] Response text: {sendQuestionsGET.text}")
                    print(f"{Fore.RED}ERROR  'questions'{Fore.RESET}")
                    print(f"{Fore.RED} [ + ] {self.email} ==> ERROR While unlock ==>{Fore.RESET}")
                    with lock:
                        with open("files/error.txt","a+")as f :
                            f.write(f'{self.data_email} - Questions parsing error: {e}\n')
                    return
                
                # Enhanced logging for question debugging
                logger.info(f"[{self.email}] Received questions from Apple:")
                logger.info(f"[{self.email}] Question 1: '{question1}' (ID: {qu_id1}, Number: {number1})")
                logger.info(f"[{self.email}] Question 2: '{question2}' (ID: {qu_id2}, Number: {number2})")
                
                # Check if questions exist in our mapping
                questions_missing = []
                if question1 not in qus:
                    logger.error(f"[{self.email}] QUESTION 1 NOT FOUND IN MAPPING: '{question1}'")
                    logger.error(f"[{self.email}] Available questions in mapping: {list(qus.keys())}")
                    print(f"{Fore.RED}[ERROR] Question 1 not found in mapping: '{question1}'{Fore.RESET}")
                    questions_missing.append(question1)
                    
                if question2 not in qus:
                    logger.error(f"[{self.email}] QUESTION 2 NOT FOUND IN MAPPING: '{question2}'")
                    logger.error(f"[{self.email}] Available questions in mapping: {list(qus.keys())}")
                    print(f"{Fore.RED}[ERROR] Question 2 not found in mapping: '{question2}'{Fore.RESET}")
                    questions_missing.append(question2)
                    
                # If any questions are missing, skip this account
                if questions_missing:
                    logger.error(f"[{self.email}] Skipping account due to missing question mappings: {questions_missing}")
                    print(f"{Fore.RED}[ERROR] {self.email} - Missing question mappings, skipping account{Fore.RESET}")
                    with lock:
                        with open("files/error.txt","a+")as f :
                            f.write(f'{self.data_email} - Missing question mappings: {questions_missing}\n')
                    return
                
                # Log the answers we're about to use
                if question1 in qus:
                    answer_index1 = qus[question1]
                    answer1 = self.data_email.split(',')[answer_index1]
                    logger.info(f"[{self.email}] Question 1 answer index: {answer_index1}, Answer: '{answer1}'")
                else:
                    logger.error(f"[{self.email}] Cannot get answer for question 1 - question not in mapping")
                    
                if question2 in qus:
                    answer_index2 = qus[question2]
                    answer2 = self.data_email.split(',')[answer_index2]
                    logger.info(f"[{self.email}] Question 2 answer index: {answer_index2}, Answer: '{answer2}'")
                else:
                    logger.error(f"[{self.email}] Cannot get answer for question 2 - question not in mapping")

                # Build payload with error handling
                try:
                    payload = {
                        "questions": [
                            {
                                "question": question1,
                                "answer": self.data_email.split(',')[qus[question1]],
                                "id": qu_id1,
                                "number": number1
                            },
                            {
                                "question": question2,
                                "answer": self.data_email.split(',')[qus[question2]],
                                "id": qu_id2,
                                "number": number2
                            }
                        ]
                    }
                    logger.info(f"[{self.email}] Payload created successfully")
                    logger.debug(f"[{self.email}] Full payload: {payload}")
                    
                    # Detailed logging of answers being sent
                    logger.info(f"[{self.email}] === DETAILED ANSWER DEBUG ===")
                    logger.info(f"[{self.email}] Answer 1 raw: '{self.data_email.split(',')[qus[question1]]}'")
                    logger.info(f"[{self.email}] Answer 1 repr: {repr(self.data_email.split(',')[qus[question1]])}")
                    logger.info(f"[{self.email}] Answer 1 bytes: {self.data_email.split(',')[qus[question1]].encode('utf-8')}")
                    logger.info(f"[{self.email}] Answer 2 raw: '{self.data_email.split(',')[qus[question2]]}'")
                    logger.info(f"[{self.email}] Answer 2 repr: {repr(self.data_email.split(',')[qus[question2]])}")
                    logger.info(f"[{self.email}] Answer 2 bytes: {self.data_email.split(',')[qus[question2]].encode('utf-8')}")
                    logger.info(f"[{self.email}] === END ANSWER DEBUG ===")
                    
                except KeyError as e:
                    logger.error(f"[{self.email}] KeyError when building payload: {e}")
                    logger.error(f"[{self.email}] Missing question in qus mapping: {e}")
                    print(f"{Fore.RED}[ERROR] {self.email} - Question mapping error: {e}{Fore.RESET}")
                    with lock:
                        with open("files/error.txt","a+")as f :
                            f.write(f'{self.data_email} - Question mapping error: {e}\n')
                    return
                except IndexError as e:
                    logger.error(f"[{self.email}] IndexError when accessing answer: {e}")
                    logger.error(f"[{self.email}] Account data: {self.data_email}")
                    print(f"{Fore.RED}[ERROR] {self.email} - Answer index error: {e}{Fore.RESET}")
                    with lock:
                        with open("files/error.txt","a+")as f :
                            f.write(f'{self.data_email} - Answer index error: {e}\n')
                    return
                logger.info(f"[{self.email}] Sending questions to Apple...")
                sendQuestionsPOST = self.session.post('https://iforgot.apple.com/password/verify/questions',headers=self.headers,json=payload)
                
                logger.info(f"[{self.email}] Questions response status: {sendQuestionsPOST.status_code}")
                logger.debug(f"[{self.email}] Questions response text: {sendQuestionsPOST.text}")
                
                if sendQuestionsPOST.status_code == 400:
                    logger.error(f"[{self.email}] Questions validation failed (400)")
                    logger.error(f"[{self.email}] Response: {sendQuestionsPOST.text}")
                    
                    # Try to parse the error response
                    try:
                        error_response = sendQuestionsPOST.json()
                        if 'serviceErrors' in error_response:
                            for error in error_response['serviceErrors']:
                                if error.get('code') == 'crIncorrect':
                                    logger.error(f"[{self.email}] Security answers incorrect: {error.get('message')}")
                                    print(f"{Fore.RED} [ + ] {self.email} ==> ERROR: Security answers incorrect{Fore.RESET}")
                                else:
                                    logger.error(f"[{self.email}] Service error: {error}")
                                    print(f"{Fore.RED} [ + ] {self.email} ==> ERROR: {error.get('message', 'Unknown error')}{Fore.RESET}")
                        else:
                            print(f"{Fore.RED} [ + ] {self.email} ==> ERROR While unlock ==> INVALID questions{Fore.RESET}")
                    except:
                        print(f"{Fore.RED} [ + ] {self.email} ==> ERROR While unlock ==> INVALID questions{Fore.RESET}")
                    
                    print(f"{Fore.RED}     Question 1: '{question1}' -> Answer: '{self.data_email.split(',')[qus[question1]]}'")
                    print(f"{Fore.RED}     Question 2: '{question2}' -> Answer: '{self.data_email.split(',')[qus[question2]]}'")
                    print(f"{Fore.YELLOW}     Suggestion: Check if the answers in Accounts.txt match your actual security question answers{Fore.RESET}")
                    with lock:
                        with open("files/error.txt","a+")as f :
                            f.write(f'{self.data_email} - Invalid security answers (400)\n')    
                    return
                if sendAppleid.status_code == 302:

                    """ * Send Options * """
                    sendOptionsGET = self.session.get(f'https://iforgot.apple.com{sendQuestionsPOST.headers["Location"]}',headers=self.headers)


                    """ * Send reset * """
                    sendResetGET = self.session.get(f'https://iforgot.apple.com{sendOptionsGET.headers["Location"]}',headers=self.headers)
                    
                    # Check if Sstt header exists in reset GET response
                    if 'Sstt' in sendResetGET.headers:
                        self.headers['sstt'] = sendResetGET.headers['Sstt']
                        logger.info(f"[{self.email}] Got Sstt token from reset GET")
                    else:
                        logger.error(f"[{self.email}] No Sstt header in reset GET response")
                        logger.error(f"[{self.email}] Available headers: {list(sendResetGET.headers.keys())}")
                        print(f"{Fore.RED}ERROR  'Sstt' - Missing Sstt header in reset response{Fore.RESET}")
                        print(f"{Fore.RED} [ + ] {self.email} ==> ERROR While unlock ==>{Fore.RESET}")
                        with lock:
                            with open("files/error.txt","a+")as f :
                                f.write(f'{self.data_email} - Missing Sstt header in reset response\n')
                        return

                    """ * RESET PASSWORD * """
                    sendResetPassword = self.session.post('https://iforgot.apple.com/password/reset',headers=self.headers,json={"password":self.new_password})
                    if sendResetPassword.status_code ==260:
                        time_ = int(time.time()) - int(start)
                        print(f"{Fore.GREEN} [ + ] {self.email} ==> Was Unlocked Successfuly in ==> {time_}s ")
                        print(f"{Fore.CYAN} [ + ] New password: {self.new_password}{Fore.RESET}")
                        with lock:
                            with open("files/Success.txt","a+")as f :
                                f.write(f'{self.data_email.replace(self.password,self.new_password)}\n')
                        # Save generated password to separate file
                        save_generated_password(self.email, self.new_password)
                    else:
                        print(f"{Fore.RED} [ + ] {self.email} ==> ERROR While unlock ==>")
                        with lock:
                            with open("files/error.txt","a+")as f :
                                f.write(f'{self.data_email}\n')     
                
        except Exception as e :
            print("ERROR ",e)
            print(f"{Fore.RED} [ + ] {self.email} ==> ERROR While unlock ==>")
            with lock:
                with open("files/error.txt","a+")as f :
                    f.write(f'{self.data_email}\n')  
with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
    futures = [executor.submit(unlocker().unlock,emails ) for emails in open('files/Accounts.txt').read().splitlines()]
    for future in concurrent.futures.as_completed(futures):
        result = future.result()
