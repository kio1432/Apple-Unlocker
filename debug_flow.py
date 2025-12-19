#!/usr/bin/env python3
"""
Debug script to trace the full iforgot.apple.com flow
Logs all redirects, headers, cookies, and responses at each step
"""

import os
import time
import json
import urllib.parse
import tls_client
from colorama import Fore, init
from datetime import datetime

init()

# Create debug log file
DEBUG_FILE = f"files/flow_debug_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

def log(message, level="INFO"):
    """Log to both console and file"""
    timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
    formatted = f"[{timestamp}] [{level}] {message}"
    print(formatted)
    with open(DEBUG_FILE, "a", encoding="utf-8") as f:
        f.write(formatted + "\n")

def log_response(step_name, response, show_body=True):
    """Log detailed response info"""
    log(f"\n{'='*60}")
    log(f"STEP: {step_name}")
    log(f"{'='*60}")
    log(f"Status Code: {response.status_code}")
    log(f"Final URL: {response.url}")
    
    # Log all headers
    log(f"\n--- Response Headers ({len(response.headers)}) ---")
    for key, value in response.headers.items():
        log(f"  {key}: {value[:100]}{'...' if len(str(value)) > 100 else ''}")
    
    # Log cookies
    log(f"\n--- Cookies ({len(response.cookies)}) ---")
    for name, value in response.cookies.items():
        log(f"  {name}: {value[:50]}{'...' if len(str(value)) > 50 else ''}")
    
    # Log body
    if show_body:
        body = response.text[:1000] if response.text else "(empty)"
        log(f"\n--- Response Body (first 1000 chars) ---")
        log(body)
    
    log(f"{'='*60}\n")

def trace_flow(email, birthday):
    """Trace the full iforgot flow step by step"""
    
    log(f"\n{'#'*60}")
    log(f"STARTING FLOW TRACE FOR: {email}")
    log(f"Birthday: {birthday}")
    log(f"{'#'*60}\n")
    
    # Setup session - disable auto redirects to see each step
    session = tls_client.Session(
        random_tls_extension_order=True,
        client_identifier="chrome_128"
    )
    
    base_headers = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.9",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
    }
    
    cookies_jar = {}
    sstt_token = None
    
    # ============================================================
    # STEP 1: Initial page load - get cookies and sstt
    # ============================================================
    log(f"{Fore.CYAN}STEP 1: Loading initial page...{Fore.RESET}")
    
    resp1 = session.get(
        'https://iforgot.apple.com/password/verify/appleid',
        headers=base_headers
    )
    log_response("1. Initial Page Load", resp1)
    
    # Extract sstt token from page
    try:
        sstt_token = urllib.parse.quote(
            resp1.text.split('"https://iforgot.apple.com","contextUrl":"/","sstt":"')[1].split('","captchaEnabled":true,')[0]
        )
        log(f"{Fore.GREEN}Extracted sstt token: {sstt_token[:50]}...{Fore.RESET}")
    except Exception as e:
        log(f"{Fore.RED}Failed to extract sstt: {e}{Fore.RESET}", "ERROR")
        return
    
    # Collect cookies
    for name, value in resp1.cookies.items():
        cookies_jar[name] = value
    
    # ============================================================
    # STEP 2: Get captcha
    # ============================================================
    log(f"\n{Fore.CYAN}STEP 2: Getting captcha...{Fore.RESET}")
    
    ajax_headers = base_headers.copy()
    ajax_headers.update({
        "accept": "application/json, text/javascript, */*; q=0.01",
        "content-type": "application/json",
        "x-requested-with": "XMLHttpRequest",
        "sstt": sstt_token,
        "cookie": '; '.join([f"{k}={v}" for k, v in cookies_jar.items()]),
        "x-apple-i-fd-client-info": '{"U":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36","L":"en-US","Z":"GMT+03:00","V":"1.1","F":""}',
    })
    
    resp2 = session.get(
        'https://iforgot.apple.com/captcha?captchaType=IMAGE',
        headers=ajax_headers
    )
    log_response("2. Get Captcha", resp2)
    
    # Update cookies
    for name, value in resp2.cookies.items():
        cookies_jar[name] = value
    
    if resp2.status_code not in [200, 401]:
        log(f"{Fore.RED}Captcha request failed{Fore.RESET}", "ERROR")
        return
    
    try:
        captcha_data = resp2.json()
        captcha_id = captcha_data.get('id', '')
        captcha_token = captcha_data.get('token', '')
        log(f"{Fore.GREEN}Captcha ID: {captcha_id}{Fore.RESET}")
    except:
        log(f"{Fore.RED}Failed to parse captcha JSON{Fore.RESET}", "ERROR")
        return
    
    # ============================================================
    # STEP 3: Solve captcha (using YesCaptcha)
    # ============================================================
    log(f"\n{Fore.CYAN}STEP 3: Solving captcha...{Fore.RESET}")
    
    try:
        from yescaptcha.task import ImageToTextTask
        from yescaptcha.client import Client
        
        with open("files/settings.json") as f:
            settings = json.load(f)
        api_key = settings.get('API_KEY', '')
        
        client = Client(client_key=api_key)
        task = ImageToTextTask(captcha_data['payload']['content'])
        job = client.create_task(task)
        captcha_answer = job.get_solution_text()
        log(f"{Fore.GREEN}Captcha solved: {captcha_answer}{Fore.RESET}")
    except Exception as e:
        log(f"{Fore.RED}Captcha solving failed: {e}{Fore.RESET}", "ERROR")
        return
    
    # ============================================================
    # STEP 4: Verify Apple ID (POST)
    # ============================================================
    log(f"\n{Fore.CYAN}STEP 4: Verifying Apple ID...{Fore.RESET}")
    
    ajax_headers['cookie'] = '; '.join([f"{k}={v}" for k, v in cookies_jar.items()])
    
    verify_data = {
        "id": email,
        "captcha": {
            "id": captcha_id,
            "answer": captcha_answer,
            "token": captcha_token
        }
    }
    
    log(f"POST data: {json.dumps(verify_data, indent=2)}")
    
    resp4 = session.post(
        'https://iforgot.apple.com/password/verify/appleid',
        headers=ajax_headers,
        json=verify_data
    )
    log_response("4. Verify Apple ID", resp4)
    
    # Update cookies and sstt
    for name, value in resp4.cookies.items():
        cookies_jar[name] = value
    
    if 'Sstt' in resp4.headers:
        sstt_token = resp4.headers['Sstt']
        log(f"{Fore.GREEN}New sstt from headers: {sstt_token[:50]}...{Fore.RESET}")
    
    # Check for errors
    if resp4.status_code == 400:
        log(f"{Fore.RED}Apple ID verification failed{Fore.RESET}", "ERROR")
        return
    
    # Check redirect location
    location = resp4.headers.get('Location', '')
    log(f"Redirect Location: {location}")
    
    # ============================================================
    # STEP 5: Follow redirect to authentication method
    # ============================================================
    if resp4.status_code == 302 and location:
        log(f"\n{Fore.CYAN}STEP 5: Following redirect to {location}...{Fore.RESET}")
        
        # Build full URL if relative
        if location.startswith('/'):
            full_url = f'https://iforgot.apple.com{location}'
        else:
            full_url = location
        
        ajax_headers['cookie'] = '; '.join([f"{k}={v}" for k, v in cookies_jar.items()])
        ajax_headers['sstt'] = sstt_token
        
        resp5 = session.get(full_url, headers=ajax_headers)
        log_response("5. Auth Method Page", resp5)
        
        for name, value in resp5.cookies.items():
            cookies_jar[name] = value
        
        if 'Sstt' in resp5.headers:
            sstt_token = resp5.headers['Sstt']
            log(f"{Fore.GREEN}New sstt: {sstt_token[:50]}...{Fore.RESET}")
        
        location = resp5.headers.get('Location', '')
    
    # ============================================================
    # STEP 6: Select recovery option (reset_password)
    # ============================================================
    log(f"\n{Fore.CYAN}STEP 6: Selecting recovery option (reset_password)...{Fore.RESET}")
    
    ajax_headers['cookie'] = '; '.join([f"{k}={v}" for k, v in cookies_jar.items()])
    ajax_headers['sstt'] = sstt_token
    
    # Use the correct endpoint - /recovery/options with option parameter
    recovery_data = {"option": "reset_password"}
    
    log(f"POST to /recovery/options with: {recovery_data}")
    
    resp6 = session.post(
        'https://iforgot.apple.com/recovery/options',
        headers=ajax_headers,
        json=recovery_data
    )
    log_response("6. Select Recovery Option", resp6)
    
    for name, value in resp6.cookies.items():
        cookies_jar[name] = value
    
    if 'Sstt' in resp6.headers:
        sstt_token = resp6.headers['Sstt']
        log(f"{Fore.GREEN}New sstt: {sstt_token[:50]}...{Fore.RESET}")
    
    location = resp6.headers.get('Location', '')
    log(f"Redirect Location: {location}")
    
    # If we got a redirect, follow it
    if resp6.status_code == 302 and location:
        log(f"\n{Fore.CYAN}STEP 6b: Following redirect to {location}...{Fore.RESET}")
        
        if location.startswith('/'):
            full_url = f'https://iforgot.apple.com{location}'
        else:
            full_url = location
        
        ajax_headers['cookie'] = '; '.join([f"{k}={v}" for k, v in cookies_jar.items()])
        ajax_headers['sstt'] = sstt_token
        
        resp6b = session.get(full_url, headers=ajax_headers)
        log_response("6b. Follow Redirect (GET authenticationmethod)", resp6b)
        
        for name, value in resp6b.cookies.items():
            cookies_jar[name] = value
        
        if 'Sstt' in resp6b.headers:
            sstt_token = resp6b.headers['Sstt']
            log(f"{Fore.GREEN}New sstt: {sstt_token[:50]}...{Fore.RESET}")
        
        # Extract sstt from JSON response if present
        try:
            data = resp6b.json()
            if 'sstt' in data:
                sstt_token = urllib.parse.quote(data['sstt'])
                log(f"{Fore.GREEN}Extracted sstt from JSON: {sstt_token[:50]}...{Fore.RESET}")
            if 'authenticationMethods' in data:
                log(f"{Fore.YELLOW}Available auth methods: {data['authenticationMethods']}{Fore.RESET}")
        except:
            pass
        
        # ============================================================
        # STEP 6c: POST to select authentication method (questions)
        # ============================================================
        log(f"\n{Fore.CYAN}STEP 6c: POST to select 'questions' auth method...{Fore.RESET}")
        
        ajax_headers['cookie'] = '; '.join([f"{k}={v}" for k, v in cookies_jar.items()])
        ajax_headers['sstt'] = sstt_token
        
        auth_method_data = {"type": "questions"}
        log(f"POST data: {auth_method_data}")
        
        resp6c = session.post(
            'https://iforgot.apple.com/password/authenticationmethod',
            headers=ajax_headers,
            json=auth_method_data
        )
        log_response("6c. POST Select Auth Method", resp6c)
        
        for name, value in resp6c.cookies.items():
            cookies_jar[name] = value
        
        if 'Sstt' in resp6c.headers:
            sstt_token = resp6c.headers['Sstt']
            log(f"{Fore.GREEN}New sstt: {sstt_token[:50]}...{Fore.RESET}")
        
        location = resp6c.headers.get('Location', '')
        log(f"Redirect Location after auth method: {location}")
        
        # Follow redirect if any
        if resp6c.status_code == 302 and location:
            log(f"\n{Fore.CYAN}STEP 6d: Following redirect to {location}...{Fore.RESET}")
            
            if location.startswith('/'):
                full_url = f'https://iforgot.apple.com{location}'
            else:
                full_url = location
            
            ajax_headers['cookie'] = '; '.join([f"{k}={v}" for k, v in cookies_jar.items()])
            ajax_headers['sstt'] = sstt_token
            
            resp6d = session.get(full_url, headers=ajax_headers)
            log_response("6d. Follow Redirect after auth method", resp6d)
            
            for name, value in resp6d.cookies.items():
                cookies_jar[name] = value
            
            if 'Sstt' in resp6d.headers:
                sstt_token = resp6d.headers['Sstt']
                log(f"{Fore.GREEN}New sstt: {sstt_token[:50]}...{Fore.RESET}")
    
    # ============================================================
    # STEP 7: GET Birthday page
    # ============================================================
    log(f"\n{Fore.CYAN}STEP 7: Getting birthday page...{Fore.RESET}")
    
    ajax_headers['cookie'] = '; '.join([f"{k}={v}" for k, v in cookies_jar.items()])
    ajax_headers['sstt'] = sstt_token
    
    resp7 = session.get(
        'https://iforgot.apple.com/password/verify/birthday',
        headers=ajax_headers
    )
    log_response("7. Birthday Page GET", resp7)
    
    for name, value in resp7.cookies.items():
        cookies_jar[name] = value
    
    if 'Sstt' in resp7.headers:
        sstt_token = resp7.headers['Sstt']
        log(f"{Fore.GREEN}New sstt: {sstt_token[:50]}...{Fore.RESET}")
    
    # Check for timeout already
    if 'session/timeout' in str(resp7.url):
        log(f"{Fore.RED}SESSION TIMEOUT at birthday GET!{Fore.RESET}", "ERROR")
        return
    
    # ============================================================
    # STEP 8: POST Birthday
    # ============================================================
    log(f"\n{Fore.CYAN}STEP 8: Posting birthday...{Fore.RESET}")
    
    # Parse birthday - use separate fields like unlocker.py does
    parts = birthday.split('/')
    month, day, year = parts[0], parts[1], parts[2]
    
    # Apple expects separate fields, not a combined string
    birthday_data = {
        "monthOfYear": month,
        "dayOfMonth": day,
        "year": year
    }
    
    log(f"Birthday data: {birthday_data}")
    
    ajax_headers['cookie'] = '; '.join([f"{k}={v}" for k, v in cookies_jar.items()])
    ajax_headers['sstt'] = sstt_token
    
    resp8 = session.post(
        'https://iforgot.apple.com/password/verify/birthday',
        headers=ajax_headers,
        json=birthday_data
    )
    log_response("8. Birthday POST", resp8)
    
    for name, value in resp8.cookies.items():
        cookies_jar[name] = value
    
    if 'Sstt' in resp8.headers:
        sstt_token = resp8.headers['Sstt']
        log(f"{Fore.GREEN}New sstt: {sstt_token[:50]}...{Fore.RESET}")
    else:
        log(f"{Fore.YELLOW}WARNING: No Sstt in birthday POST response{Fore.RESET}", "WARN")
    
    location = resp8.headers.get('Location', '')
    log(f"Redirect Location: {location}")
    
    # ============================================================
    # STEP 9: GET Questions page
    # ============================================================
    log(f"\n{Fore.CYAN}STEP 9: Getting questions page...{Fore.RESET}")
    
    ajax_headers['cookie'] = '; '.join([f"{k}={v}" for k, v in cookies_jar.items()])
    ajax_headers['sstt'] = sstt_token
    
    resp9 = session.get(
        'https://iforgot.apple.com/password/verify/questions',
        headers=ajax_headers
    )
    log_response("9. Questions Page GET", resp9)
    
    # Check final URL for timeout
    if 'session/timeout' in str(resp9.url):
        log(f"\n{Fore.RED}{'!'*60}")
        log(f"SESSION TIMEOUT DETECTED!")
        log(f"This means Apple rejected the session")
        log(f"{'!'*60}{Fore.RESET}")
    else:
        # Try to parse questions
        try:
            data = resp9.json()
            if 'questions' in data:
                log(f"\n{Fore.GREEN}SUCCESS! Got {len(data['questions'])} questions{Fore.RESET}")
                for q in data['questions']:
                    log(f"  Q{q['number']}: {q['question']}")
            else:
                log(f"{Fore.YELLOW}No questions in response. Keys: {list(data.keys())}{Fore.RESET}")
        except:
            log(f"{Fore.YELLOW}Response is not JSON{Fore.RESET}")
    
    # ============================================================
    # Summary
    # ============================================================
    log(f"\n{'#'*60}")
    log(f"FLOW TRACE COMPLETE")
    log(f"Debug log saved to: {DEBUG_FILE}")
    log(f"{'#'*60}")


def main():
    # Read accounts from Accounts.txt
    try:
        with open('files/Accounts.txt', 'r', encoding='utf-8') as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}Error: files/Accounts.txt not found{Fore.RESET}")
        return
    
    if not lines:
        print(f"{Fore.YELLOW}No accounts in Accounts.txt{Fore.RESET}")
        return
    
    # Use second account (index 1) if available, otherwise first
    account_index = 1 if len(lines) > 1 else 0
    parts = lines[account_index].split(',')
    if len(parts) < 6:
        print(f"{Fore.RED}Account format must be: email,password,ans1,ans2,ans3,MM/DD/YYYY{Fore.RESET}")
        return
    
    email = parts[0]
    birthday = parts[5]
    
    print(f"{Fore.CYAN}Starting flow trace for: {email}{Fore.RESET}")
    print(f"{Fore.CYAN}Debug log will be saved to: {DEBUG_FILE}{Fore.RESET}\n")
    
    trace_flow(email, birthday)


if __name__ == "__main__":
    main()
