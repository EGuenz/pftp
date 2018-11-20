#!/usr/bin/env python3
from __future__ import print_function
import argparse
import socket
import sys
import select
import ipaddress
import threading
import time
import re
from queue import Queue
from ast import literal_eval as make_tuple

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def test_order():
    if '-f' in sys.argv and '-s' in sys.argv:
        if sys.argv.index('-f') < sys.argv.index('-s'):
            return False
    if '-f' in sys.argv and '--server' in sys.argv:
        if sys.argv.index('-f') < sys.argv.index('--server'):
            return False
    if '--file' in sys.argv and '--server' in sys.argv:
        if sys.argv.index('--file') < sys.argv.index('--server'):
            return False
    if '--file' in sys.argv and '-s' in sys.argv:
        if sys.argv.index('--file') < sys.argv.index('-s'):
            return False
    return True

def file_write(f, text, s):
    try:
      f.write(text)
    except IOError:
      s.close()
      return '7: Error writing to file', 7

    return '0: Success', 0

def get_file_size(response):
    size = re.findall('\d+', response).pop()
    return int(size)

def send_with_response(sock, message, error, error_message, expected_response, log):
    if log is not None and message is not None:
       log.write("C -> S: " + message)
    sock.sendall(message.encode('utf-8'))
    response = sock.recv(1024).decode("utf-8")
    if log is not None and response is not None:
       log.write("S -> C: " + response)
    if not response or expected_response not in response:
      sock.close()
      eprint(error_message)
      exit(error)
    return response

# returns ipv4 and portno parsed from server response to PASV
def parse_pasv_response(resp):
     tup = make_tuple(resp[26:len(resp) - 3])
     tupStrs = [str(x) for x in tup]
     ipstr = ".".join(tupStrs[:4])
     ip = ipaddress.ip_address(ipstr)
     portno = (tup[4] * 256) + tup[5]
     return ip, portno

def ftp_listen(ip, port, file, queue):
    try:
        servSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as err:
        return

    try:
        servSock.connect((str(ip), port))
    except Exception as err:
        servSock.close()
        return

    bytes_expected = queue.get()
    #print(bytes_expected)
    #wait for file to be downloaded
    time.sleep(.3)
    response = servSock.recv(1024)
    length = len(response)

    if length <= 0:
        servSock.close()
        return

    try:
      f = open(file, "ab")
    except IOError:
        servSock.close()
        return

    file_write(f, response, servSock)
    totalRec = length
    while totalRec < bytes_expected:
      response = servSock.recv(1024)
      length = len(response)
      if length <= 0:
          break
      totalRec += length
      file_write(f, response, servSock)

    #print ("Num of bytes received: " + str(totalRec))
    servSock.close()
    return

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
      if len(sys.argv)==1:
         parser.print_help()
         sys.exit(0)
      if ('-h' not in sys.argv and '--help' not in sys.argv and
          '--version' not in sys.argv and '-v' not in sys.argv and
          len(sys.argv) != 1):
            eprint("4: Syntax Error in client request")
            exit(4)
      else:
            return

  if not test_order():
     parser.print_help()
     eprint("4: Syntax Error in client request, server comes before file")
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
  log = None
  if args.log is not None:
      log = open(args.log, "a")

  response = s.recv(1024).decode("utf-8")
  if log is not None and response is not None:
     log.write("S -> C: " + response)
  if "220" not in response:
     exit(1)

  message = "USER " + args.username + "\r\n"
  send_with_response(s, message, 2, "2: Authentication failed", "331", log)

  message = "PASS " + args.password + "\r\n"
  send_with_response(s, message, 2, "2: Authentication failed", "230", log)

  #message = "LIST\r\n"
  #send_with_response(s, message, 5, "5: Command not implemented by server", "425")

  message = "PASV\r\n"
  response = send_with_response(s, message, 5, "5: Command PASV not implemented by server", "227", log)
  ip, port = parse_pasv_response(response)

  q = Queue()

  try:
     t = threading.Thread(target=ftp_listen, args=(ip, port, args.file, q))
     t.start()
  except:
     eprint('7: Unable to start thread')
     exit(7)

  message = "RETR " + args.file + "\r\n"
  response = send_with_response(s, message, 3, "3: File not found", "150", log)

  #send file_size to thread
  total_bytes = get_file_size(response)
  q.put(total_bytes)

  t.join()
  response = s.recv(1024).decode("utf-8")
  if log is not None and response is not None:
     log.write("S -> C: " + response)
  if not response or "226" not in response:
    s.close()
    eprint("5: File was not downloaded")
    exit(5)

  message = "QUIT\r\n"
  send_with_response(s, message, 7, "7: Cannot Quit", "221", log)
  s.close()


main()
