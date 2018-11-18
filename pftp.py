#!/usr/bin/env python3
import argparse
import socket
import sys

def main():

  parser = argparse.ArgumentParser(description='Command line options ftp client',
                                   usage = " pftp [-s hostname] [-f file] [options]\n\tpftp -h | --help\n\tpftp -v | --version")
  parser.add_argument("-v", "--version", action = 'version', version = "FTP client v1.0 Eli Guenzburger")
  parser.add_argument("-s", "--server", metavar = "hostname", nargs = 1, help = "Specifies the server to download the file from", required=True)
  parser.add_argument("-f", "--file", metavar = "filename", nargs = 1, help = "Specify file to download", required=True)
  parser.add_argument("-p", "--port", metavar = "port", nargs = 1, type=int, default = 21, help = "Specifies the port to be used when contacting the server. (default value: 21).")
  parser.add_argument("-n", "--username", metavar = "user", nargs = 1, default = "anonymous", help = "Uses the username user when logging into the FTP server (default value: anonymous).")
  parser.add_argument("-P", "--password", metavar = "password", nargs = 1, default = "user@localhost.localnet", help = "Uses the password password when logging into the FTP server (default value:user@localhost.localnet)")
  parser.add_argument("-l", "--log", metavar = "logfile", nargs = 1, help = "Logs all the FTP commands exchanged with the server and the corresponding replies to file logfile")
  args = parser.parse_args()

  try:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  except socket.error as err:
      raise Exception('Error creating socket')

  try:
      host_ip = socket.gethostbyname(args.server)
  except socket.gaierror:
      raise Exception('Error resolving host')

  s.connect((host_ip, args.port))

  print "the socket has successfully connected to %s on port == %s" %(args.server) %(host_ip)
