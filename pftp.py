#!/usr/bin/env python3
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

class ThrowingArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        exit(4)

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def correct_order():
    if '-s' in sys.argv and sys.argv.index('-s') != 1:
            return False
    elif '--server' in sys.argv and sys.argv.index('--sever') != 1:
            return False

    if '-f' in sys.argv and sys.argv.index('-f') != 3:
            return False
    elif '--file' in sys.argv and sys.argv.index('--file') != 3:
            return False

    else:
        if '-t' in sys.argv and sys.argv.index('-t') != 1:
                return False
        elif '--thread' in sys.argv and sys.argv.index('--thread') != 1:
                return False
    return True

#returns starting download position and number of bytes to read for thread
def download_position(t_count, num_threads, file_size):
   download_size = file_size // num_threads
   read_bytes = download_size
   if (t_count == num_threads - 1):
       read_bytes += (file_size % num_threads)
   starting_pos = download_size * t_count
   return starting_pos, read_bytes

def parse_config_line(line, num_threads, t_count, port, logfile):
    try:
      if line.find('ftp://') == 0:
         line = line[6:]
      username = line[:line.find(':')]
      password = line[:line.find('@')]
      line = line[line.find('@') + 1:]
      server = line[:line.find('/')]
      line = line[line.find('/') + 1:]
      file = line
    except:
      return None

    args = {
    'server' : server,
    'file' : file,
    'username' : username,
    'password' : password,
    'port' : port,
    'logfile' : logfile,
    't_count' : t_count,
    'num_threads' : num_threads
    }
    return args

def parse_config(args):
    if not hasattr(args, 'thread'):
        argdict = args = {
        'server' : args.server,
        'file' : args.file,
        'username' : args.username,
        'password' : args.password,
        'port' : args.port,
        'logfile' : args.log,
        't_count' : 0,
        'num_threads' : 1
        }
        return [argdict]
    try:
        f = open(args.thread, 'r')
    except IOError:
        return None, 7, "Error opening file"

    line_count = 0
    for line in f:
        line_count += 1

    thread_list = []
    t_count = 0
    for line in f:
       t_count += 1
       argdict = parse_config_line(line, line_count, t_count, args.port, args.log)
       if argdict is None:
           return None, 4, "Syntax Error in Config file"
       list.append(argdict)
    return list, 0, ""


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

def send_with_response(sock, message, error, error_message, expected_response, log, lock):
    if log is not None and message is not None:
       lock.acquire()
       log.write("C -> S: " + message)
       lock.release()
    sock.sendall(message.encode('utf-8'))
    response = sock.recv(1024).decode("utf-8")
    if log is not None and response is not None:
       lock.acquire()
       log.write("S -> C: " + response)
       lock.release()
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

def ftp_listen(ip, port, f, queue):
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

def parse_args():
    parser = ThrowingArgumentParser(description='Command line options ftp client',
                                    usage = " pftp [-s hostname] [-f file] [options]\n\tpftp [-t config-file] [options]\n\tpftp -h | --help\n\tpftp -v | --version")

    parser2 = ThrowingArgumentParser(description='Command line options ftp client',
                                     usage = " pftp [-s hostname] [-f file] [options]\n\tpftp [-t config-file] [options]\n\tpftp -h | --help\n\tpftp -v | --version")

    parser.add_argument("-v", "--version", action = 'version', version = "FTP client v1.0 Eli Guenzburger")
    parser2.add_argument("-v", "--version", action = 'version', version = "FTP client v1.0 Eli Guenzburger")
    parser.add_argument("-s", "--server", metavar = "hostname", help = "Specifies the server to download the file from", required = True)
    parser.add_argument("-f", "--file", metavar = "filename", help = "Specify file to download", required = True)
    parser2.add_argument("-t", "--thread", metavar = "config-file", help = "Specify para-config file", required = True)
    parser.add_argument("-p", "--port", metavar = "port", type=int, default = 21, help = "Specifies the port to be used when contacting the server. (default value: 21).")
    parser2.add_argument("-p", "--port", metavar = "port", type=int, default = 21, help = "Specifies the port to be used when contacting the server. (default value: 21).")
    parser.add_argument("-n", "--username", metavar = "user", default = "anonymous", help = "Uses the username user when logging into the FTP server (default value: anonymous).")
    parser2.add_argument("-n", "--username", metavar = "user", default = "anonymous", help = "Uses the username user when logging into the FTP server (default value: anonymous).")
    parser.add_argument("-P", "--password", metavar = "password", default = "user@localhost.localnet", help = "Uses the password password when logging into the FTP server (default value:user@localhost.localnet)")
    parser2.add_argument("-P", "--password", metavar = "password", default = "user@localhost.localnet", help = "Uses the password password when logging into the FTP server (default value:user@localhost.localnet)")
    parser.add_argument("-l", "--log", metavar = "logfile", help = "Logs all the FTP commands exchanged with the server and the corresponding replies to file logfile")
    parser2.add_argument("-l", "--log", metavar = "logfile", help = "Logs all the FTP commands exchanged with the server and the corresponding replies to file logfile")


    try:
        args = parser.parse_args()

    except SystemExit:
        if len(sys.argv)==1:
           parser.print_help()
           exit(0)

        if ('-h' not in sys.argv and '--help' not in sys.argv and
            '--version' not in sys.argv and '-v' not in sys.argv):

            try :
                args = parser2.parse_args()
            except SystemExit:
                parser.print_help()
                eprint("4: Syntax Error in client request")
                exit(4)
        else:
              exit(0)

    if not correct_order():
       parser.print_help()
       eprint("4: Syntax Error in client request, out of order")
       exit(4)

    return args

def execute_ftp(args, log, file, lock):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    except socket.error as err:
        eprint('1: Cant connect to server')
        exit(1)

    try:
        host_ip = socket.gethostbyname(args["server"])
    except socket.gaierror:
        s.close()
        eprint('1: Cant connect to server')
        exit(1)

    #s.settimeout(5.0)
    try:
        s.connect((host_ip, args["port"]))
    except Exception as err:
        s.close()
        eprint('1: Cant connect to server')
        exit(1)

    response = s.recv(1024).decode("utf-8")
    if log is not None and response is not None:
       lock.acquire()
       log.write("S -> C: " + response)
       lock.release()
    if "220" not in response:
       exit(1)

    message = "USER " + args["username"] + "\r\n"
    send_with_response(s, message, 2, "2: Authentication failed", "331", log, lock)

    message = "PASS " + args["password"] + "\r\n"
    send_with_response(s, message, 2, "2: Authentication failed", "230", log, lock)

    message = "PASV\r\n"
    response = send_with_response(s, message, 5, "5: Command PASV not implemented by server", "227", log, lock)
    ip, port = parse_pasv_response(response)

    q = Queue()

    try:
       t = threading.Thread(target=ftp_listen, args=(ip, port, file, q))
       t.start()
    except:
       eprint('7: Unable to start listening thread')
       exit(7)

    message = "SIZE " + args["file"] + "\r\n"
    response = send_with_response(s, message, 3, "3: File not found on SIZE", "213 ", log, lock)
    file_size = get_file_size(response)
    starting_pos, read_size = download_position(args["t_count"], args["num_threads"], file_size)

    message = "REST " + str(starting_pos) + "\r\n"
    send_with_response(s, message, 5, "5: Server will not set file position", "350 ", log, lock)
    #send read_size to thread
    q.put(read_size)

    message = "RETR " + args["file"] + "\r\n"
    send_with_response(s, message, 3, "3: File not found on RETR", "150", log, lock)

    t.join()
    response = s.recv(1024).decode("utf-8")
    if log is not None and response is not None:
       lock.acquire()
       log.write("S -> C: " + response)
       lock.release()
    if not response or "226" not in response:
      s.close()
      eprint("5: File was not downloaded")
      exit(5)

    message = "QUIT\r\n"
    send_with_response(s, message, 7, "7: Cannot Quit", "221", log, lock)
    s.close()

def main():
   args = parse_args()
   thread_list = parse_config(args)

   log = None
   if args.log is not None:
      log = open(args.log, "w")

   try:
     f = open(thread_list[0]["file"], "wb")
   except IOError:
       servSock.close()
       return

   lock = threading.Lock()
   for t in thread_list:
     try:
        thread = threading.Thread(target=execute_ftp, args=(t, log, f, lock))
        thread.start()
        thread.join()
     except:
        eprint('7: Unable to start thread')
        exit(7)



main()
