#!/usr/bin/env python3
from __future__ import print_function
import argparse
import socket
import sys

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def send_with_response(sock, message, error, expected_response):
    print(message)
    sock.sendall(message.encode('utf-8'))

    response = sock.recv(1024).decode("utf-8")
    print(response)
    if expected_response not in response:
        exit(error)

def main():

  parser = argparse.ArgumentParser(description='Command line options ftp client',
                                   usage = " pftp [-s hostname] [-f file] [options]\n\tpftp -h | --help\n\tpftp -v | --version")
  parser.add_argument("-v", "--version", action = 'version', version = "FTP client v1.0 Eli Guenzburger")
  parser.add_argument("-s", "--server", metavar = "hostname", help = "Specifies the server to download the file from", required=True)
  parser.add_argument("-f", "--file", metavar = "filename", help = "Specify file to download", required=True)
  parser.add_argument("-p", "--port", metavar = "port", type=int, default = 21, help = "Specifies the port to be used when contacting the server. (default value: 21).")
  parser.add_argument("-n", "--username", metavar = "user", default = "anonymous", help = "Uses the username user when logging into the FTP server (default value: anonymous).")
  parser.add_argument("-P", "--password", metavar = "password", default = "user@localhost.localnet", help = "Uses the password password when logging into the FTP server (default value:user@localhost.localnet)")
  parser.add_argument("-l", "--log", metavar = "logfile", help = "Logs all the FTP commands exchanged with the server and the corresponding replies to file logfile")

  try:
      args = parser.parse_args()

  except SystemExit:
      eprint("Syntax Error")
      exit(4)

  try:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  except socket.error as err:
      eprint('Error creating socket')
      exit(1)

  try:
      host_ip = socket.gethostbyname(args.server)
  except socket.gaierror:
      eprint('Error resolving host')
      exit(1)

  try:
      s.connect((host_ip, args.port))
  except Exception as err:
      eprint('Error connection to server')
      exit(1)

  response = s.recv(1024).decode("utf-8")

  print(response)
  if "220" not in response:
     exit(1)

  message = "USER " + args.username

  send_with_response(s, message, 1, "331")

  message = "PASS" + args.password

  send_with_response(s, message, 2, "230")


  s.close()

  ##print("the socket has successfully connected to google on port == " + host_ip)


main()
