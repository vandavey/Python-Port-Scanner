#!/usr/bin/python3
import os
import argparse
import socket
import ipaddress
import threading
from queue import Queue
from datetime import datetime

# TODO: add logic for output option

def print_banner(start_time, target):
  print("-" * 40)
  print(f"Beginning scan on target {target}")
  print("-" * 40)
  print(f"Scan start time: {start_time}\n")


def scan_port(ipaddr, port):
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  try:
    connection = sock.connect_ex((ipaddr, port))
    if connection == 0:
      with printlock:
        print(f"Port {port}: Open")
    connection.close()
  except:
    pass


def threader():
  while True:
    worker = queue.get()
    scan_port(target, worker)
    queue.task_done()


def get_stats(start_time, end_time):
  total_secs = (end_time - start_time).total_seconds()
  minutes = int(str(total_secs / 60).split(".") [0])
  seconds = round(total_secs - (minutes * 60), 3)
  print(f"\nScan lasted {minutes} minutes, {seconds} seconds")
  print("-" * 40 + "\n")


parser = argparse.ArgumentParser(
  prog="portscan.py",
  description="python multithreaded port scanner",
  usage="portscan.py [-h] [-c] [-a] [-A] [-o OUTFILE] [-t THREADS] [-p PORT] TARGET"
)

parser.add_argument(
  "-c", "--common",
  action="store_true",
  help="scan common ports (0-1024), overrides [-p]"
)

parser.add_argument(
  "-a", "--all",
  action="store_true",
  help="scan all ports (0-65535), overrides [-p]"
)

parser.add_argument(
  "-A", "--aggressive",
  action="store_true",
  help="run an aggressive scan (same as --threads 200)"
)

parser.add_argument(
  "-o", "--outfile",
  type=str,
  help="specify text file path to save results"
)

parser.add_argument("TARGET", type=str, help="target ip address")
parser.add_argument("-t", "--threads", type=int, help="number of threads")
parser.add_argument("-p", "--port", type = str, help="port/port range to scan")

args = parser.parse_args()
target = args.TARGET

ports = args.port
outfile = args.outfile
threads = args.threads

common = args.common
aggressive = args.aggressive
all = args.all

except_thrown = False
prange = range(0)

if threads == None:
  if aggressive:
    threads = 200
  else:
    threads = 85
else:
  if aggressive:
    threads = 200

if ports != None:
  if "-" in ports:
    new = str(ports).split("-")
    prange = range(int(new[0]), int(new[1]))
  else:
    if str(ports).isdecimal():
      if not 0 < int(ports) <= 65535:
        raise ValueError("<PORT> must be between 0-65535")
    else:
      raise ValueError("<PORT> must be of type integer")
else:
  if all:
    prange = range(65535)
  else:
    prange = range(1025)

queue = Queue()
queue.maxsize = 5

socket.setdefaulttimeout(.5)
printlock = threading.Lock()

start_time = datetime.now()
print_banner(start_time, target)

for worker in range(threads):
  thread = threading.Thread(target=threader)
  thread.daemon = True
  thread.start()

for port in prange:
  try:
    queue.put(port)
  except KeyboardInterrupt:
    except_thrown = True
    break

try:
  queue.join()
except KeyboardInterrupt:
  except_thrown = True

if except_thrown:
  print("\nScan interrupted by user, now exiting")

end_time = datetime.now()
get_stats(start_time, end_time)
