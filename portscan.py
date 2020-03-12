#!/usr/bin/python3
import argparse
from scapy.all import *
import ipaddress as ip
from pathlib import Path
from scapy.layers.inet import IP, ICMP
from queue import Queue


def is_ipv4(target):
  try:
    ip.IPv4Address(target)
    return True
  except:
    return False


def is_integer(port):
  try:
    int(port)
    return True
  except:
    return False


def ping(target):
  pckt  = IP(dst=target) / ICMP()
  response  = sr1(pckt, timeout=5, verbose=0)
  if response:
    return True
  else:
    return False


def banner(start_time, target, **kwargs):
  output = kwargs.get("output")
  if output:
    with open(output, "a+") as stream:
      stream.write(("-" * 40) + "\n")
      stream.write(f"Beginning scan on target {target}\n")
      stream.write(("-" * 40) + "\n")
      stream.write(f"Scan start time: {start_time}\n\n")
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
        if output:
          with open(output, "a+") as stream:
            stream.write(f"Port {port}: Open\n")
    connection.close()
  except:
    pass


def threader():
  while True:
    worker = queue.get()
    scan_port(target, worker)
    queue.task_done()


def get_stats(start_time, end_time, **kwargs):
  output = kwargs.get("output")
  total_secs = (end_time - start_time).total_seconds()
  minutes = int(str(total_secs / 60).split(".") [0])
  seconds = round(total_secs - (minutes * 60), 3)
  if output:
    with open(output, "a+") as stream:
      stream.write(f"\nScan lasted {minutes} minutes, {seconds} seconds\n")
      stream.write("-" * 40 + "\n\n")
  print(f"\nScan lasted {minutes} minutes, {seconds} seconds")
  print("-" * 40 + "\n")


parser = argparse.ArgumentParser(
  prog="portscan.py",
  usage="portscan.py [-h] [-c] [-a] [-A] [-o OUTFILE] [-t THREADS] [-p PORT] TARGET",
  description="python multithreaded port scanner"
)

parser.add_argument("TARGET", type=str, help="target ip address")
parser.add_argument("-t", "--threads", type=int, help="number of threads")
parser.add_argument("-p", "--port", help="port/port range to scan (overrides [-c] and [-a]")
parser.add_argument("-o", "--output", type=str, help="file path to save results")

parser.add_argument("-c", "--common", action="store_true", help="scan common ports (0-1024)")
parser.add_argument("-a", "--all", action="store_true", help="scan all ports (0-65535)")
parser.add_argument("-i", "--intense", action="store_true", help="run scan with 200 threads")
parser.add_argument("-f", "--force", action="store_true", help="don't ping target before scan")

args = parser.parse_args()
target = args.TARGET

ports = args.port
output = args.output
threads = args.threads

common = args.common
intense = args.intense
all = args.all
force = args.force

stream = None
except_thrown = False
prange = range(0)

if not is_ipv4(target):
  raise ValueError("<TARGET> argument is not valid IPv4 address")

if not force:
  if not ping(target):
    raise ValueError("<TARGET> isn't responding to our ping, use [-f] to scan anyways")

if threads == None:
  if intense:
    threads = 200
  else:
    threads = 85
else:
  if intense:
    threads = 200

if output:
  parent = Path(output).parent
  if Path.is_dir(parent):
    if Path.is_file(Path(output)):
      with open(f"{output}", "r+") as stream:
        stream.truncate()
    else:
      Path.touch(output)
  else:
    raise ValueError("Parent directory file path does not exist")

if ports != None:
  if "-" in ports:
    new = str(ports).split("-")
    prange = range(int(new[0]), int(new[1]) + 1)
  else:
    if is_integer(ports):
      if not 0 < int(ports) <= 65535:
        raise ValueError("<PORT> must be between 0-65535")
      else:
        prange = range(int(ports), int(ports) + 1)
    else:
      raise ValueError("<PORT> must be of type integer")
else:
  if all:
    prange = range(65536)
  else:
    prange = range(1025)

socket.setdefaulttimeout(.5)

queue = Queue()
queue.maxsize = 5

printlock = threading.Lock()
start_time = datetime.now()

if output:
  banner(start_time, target, output=output)
else:
  banner(start_time, target)

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

if output:
  get_stats(start_time, datetime.now(), output=output)
else:
  get_stats(start_time, datetime.now())
