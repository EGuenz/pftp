#!/usr/bin/env python3
from __future__ import print_function
import argparse
import socket
import sys
import select
import ipaddress
from ast import literal_eval as make_tuple

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def send_with_response(sock, message, error, error_message, expected_response):
    print(message)
    sock.sendall(message.encode('utf-8'))
    response = sock.recv(1024).decode("utf-8")
    print(response)
    if not response or expected_response not in response:
      sock.close()
      eprint(error_message)
      exit(error)
    return response

# returns ipv4 and portno parsed from server response to PASV
 def parse_pasv_response(response):
     tup = make_tuple(resp[26:len(resp) - 1])
     ipstr = ".".join(tup[:4])
     ip = ipaddress.ip_address(ipstr)
     portno = (int(tup[4]) * 256) + int(tup[5])
     return ip, portno


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
      eprint("4: Syntax Error in client request")
      exit(4)

  try:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  except socket.error as err:
      eprint('1: Cant connect to server')
      exit(1)

  try:
      host_ip = socket.gethostbyname(args.server)
  except socket.gaierror:
      s.close()
      eprint('1: Cant connect to server')
      exit(1)

  s.settimeout(5.0)
  try:
      s.connect((host_ip, args.port))
  except Exception as err:
      s.close()
      eprint('1: Cant connect to server')
      exit(1)

 #s.setblocking(0)
 #ready = select.select([s], [], [], 3)
 #if ready[0]:
 #    response = s.recv(1024).decode("utf-8")

  response = s.recv(1024).decode("utf-8")
  print(response)
  if "220" not in response:
     exit(1)

  message = "USER " + args.username + "\r\n"
  send_with_response(s, message, 2, "2: Authentication failed", "331")

  message = "PASS " + args.password + "\r\n"
  send_with_response(s, message, 2, "2: Authentication failed", "230")

  message = "LIST\r\n"
  send_with_response(s, message, 4, "4: Syntax error in client request", "425")

  message = "PASV\r\n"
  response = send_with_response(s, message, 4, "4: Syntax error in client request", "227")
  ip, port = parse_pasv_response(response)

  s.close()


main()
