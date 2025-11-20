#!/usr/bin/env python3
"""
Cisco Professional Attack Syslog Generator
- RFC3164-like format (PRI, Timestamp, Hostname, TAG, Message)
- Attack simulation: SYN, FIN, NULL, XMAS, Aggressive, UDP/ICMP sweep, SSH brute, DoS
- TCP/UDP sending to SIEM (Splunk/ELK/QRadar)
- Multi-threaded, adjustable intensity, Burst mode
"""

import socket, random, threading, time
from datetime import datetime
from typing import List, Tuple

# ----------------------------
# CONFIGURATION
# ----------------------------
SIEM_IP = "127.0.0.1"
SIEM_PORT = 514
USE_TCP = False
HOSTNAMES = ["Cisco-Router-Core-1", "ASA-5506", "Edge-Router"]
FACILITY = 23  # local7
DEFAULT_SEVERITY = 6  # info

INTENSITY = "high"  # low / medium / high / extreme
BURST_MODE = False
BURST_SIZE = 100
THREADS = 2

SRC_IP_RANGES = [("10.0.0.0","10.255.255.255"), ("192.168.0.0","192.168.255.255")]
DST_POOL = ["10.8.115.1","10.8.115.5","192.168.1.20"]
ACL_POOL = ["101", "102", "BLOCK-INBOUND", "EDGE-FILTER"]
PORT_CHOICES = [21,22,23,25,53,80,110,139,143,443,445,3306,3389,8080]

SEQUENCE_START = random.randint(1000,9999)

INTENSITY_MAP = {"low":1.5,"medium":0.5,"high":0.12,"extreme":0.01}

# ----------------------------
# Attack templates (Cisco-style TAG + Message)
# ----------------------------
ATTACK_TEMPLATES = {
    "SYN":"%SEC-6-IPACCESSLOGP: list {acl} denied tcp {src}({sport}) -> {dst}({dport}), SYN scan detected",
    "FIN":"%SEC-6-IPACCESSLOGP: list {acl} denied tcp {src}({sport}) -> {dst}({dport}), FIN scan detected",
    "NULL":"%SEC-6-IPACCESSLOGP: list {acl} denied tcp {src}({sport}) -> {dst}({dport}), NULL scan detected",
    "XMAS":"%SEC-6-IPACCESSLOGP: list {acl} denied tcp {src}({sport}) -> {dst}({dport}), XMAS scan detected",
    "AGGRESSIVE":"%FIREWALL-4-SCANDETECT: Aggressive port scan detected from {src} to {dst}",
    "UDP_SWEEP":"%FIREWALL-4-UDP_SWEEP: UDP sweep detected from {src} targeting multiple ports on {dst}",
    "ICMP_SWEEP":"%FIREWALL-4-ICMP_SWEEP: ICMP ping sweep detected from {src}",
    "SSH_BRUTE":"%AUTH-3-LOGIN_FAILED: Login failed for user admin from {src} via SSH",
    "DOS":"%FIREWALL-3-DOS_ATTACK: Possible DoS attack detected from {src} to {dst}"
}

# ----------------------------
# UTILITIES
# ----------------------------
def ip_from_int(n: int) -> str:
    return f"{(n>>24)&0xFF}.{(n>>16)&0xFF}.{(n>>8)&0xFF}.{n&0xFF}"

def ip_to_int(ip: str) -> int:
    a,b,c,d = map(int, ip.split('.'))
    return (a<<24)|(b<<16)|(c<<8)|d

def random_ip_from_range(rng: Tuple[str,str]) -> str:
    start, end = ip_to_int(rng[0]), ip_to_int(rng[1])
    return ip_from_int(random.randint(start, end))

def small_rand_private() -> str:
    rng = random.choice(SRC_IP_RANGES)
    return random_ip_from_range(rng)

def timestamp_rfc3164() -> str:
    return datetime.now().strftime("%b %d %H:%M:%S")

def calc_pri(facility: int, severity: int) -> int:
    return (facility << 3) + severity

def next_sequence() -> int:
    global SEQUENCE_START
    SEQUENCE_START += 1
    return SEQUENCE_START

# ----------------------------
# Syslog senders
# ----------------------------
def send_udp(msg: str, ip: str, port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg.encode(), (ip, port))
    sock.close()

def send_tcp(msg: str, ip: str, port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect((ip, port))
        sock.sendall(msg.encode()+b"\n")
    except: pass
    finally: sock.close()

def send_syslog(msg: str):
    if USE_TCP: send_tcp(msg, SIEM_IP, SIEM_PORT)
    else: send_udp(msg, SIEM_IP, SIEM_PORT)

# ----------------------------
# Build syslog message (Cisco RFC3164)
# ----------------------------
def build_syslog_message(hostname: str, message: str, severity: int = DEFAULT_SEVERITY) -> str:
    pri = calc_pri(FACILITY, severity)
    ts = timestamp_rfc3164()
    seq = next_sequence()
    return f"<{pri}>{ts} {hostname} {seq}: {message}"

# ----------------------------
# Attack generators
# ----------------------------
def generate_scan_event(scan_type: str, src: str=None, dst: str=None) -> str:
    src = src or small_rand_private()
    dst = dst or random.choice(DST_POOL)
    template = ATTACK_TEMPLATES.get(scan_type,"AGGRESSIVE")
    msg = template.format(acl=random.choice(ACL_POOL), src=src, dst=dst,
                          sport=random.randint(1024,65000), dport=random.choice(PORT_CHOICES))
    hostname = random.choice(HOSTNAMES)
    sev = 4 if scan_type in ("AGGRESSIVE","DOS") else 6
    return build_syslog_message(hostname, msg, severity=sev)

def generate_aggressive_sequence(src_base:str=None,dst:str=None,port_count:int=30)->List[str]:
    src_base = src_base or small_rand_private()
    dst = dst or random.choice(DST_POOL)
    msgs = []
    for _ in range(port_count):
        dport=random.choice(PORT_CHOICES+list(range(1024,1035)))
        template=random.choice([ATTACK_TEMPLATES["SYN"],ATTACK_TEMPLATES["FIN"],ATTACK_TEMPLATES["NULL"],ATTACK_TEMPLATES["XMAS"]])
        msg=template.format(acl=random.choice(ACL_POOL), src=src_base, dst=dst, sport=random.randint(1024,65000), dport=dport)
        hostname=random.choice(HOSTNAMES)
        msgs.append(build_syslog_message(hostname,msg,severity=4))
    return msgs

def generate_udp_sweep(src:str=None,dst:str=None,ports:int=20)->List[str]:
    src = src or small_rand_private()
    dst = dst or random.choice(DST_POOL)
    msgs=[]
    for _ in range(ports):
        msg = ATTACK_TEMPLATES["UDP_SWEEP"].format(src=src,dst=dst)
        hostname = random.choice(HOSTNAMES)
        msgs.append(build_syslog_message(hostname,msg,severity=4))
    return msgs

def generate_icmp_sweep(src:str=None,count:int=10)->List[str]:
    src=src or small_rand_private()
    msgs=[]
    for _ in range(count):
        msg=ATTACK_TEMPLATES["ICMP_SWEEP"].format(src=src)
        hostname=random.choice(HOSTNAMES)
        msgs.append(build_syslog_message(hostname,msg,severity=4))
    return msgs

def generate_ssh_brute(src:str=None,attempts:int=5)->List[str]:
    src=src or small_rand_private()
    msgs=[]
    for _ in range(attempts):
        msg=ATTACK_TEMPLATES["SSH_BRUTE"].format(src=src)
        hostname=random.choice(HOSTNAMES)
        msgs.append(build_syslog_message(hostname,msg,severity=3))
    return msgs

# ----------------------------
# Orchestrator
# ----------------------------
def orchestrate_once()->List[str]:
    msgs=[]
    delay = INTENSITY_MAP.get(INTENSITY,0.5)
    weights = {
        "low":[("SYN",0.3),("ICMP_SWEEP",0.1),("SSH_BRUTE",0.05)],
        "medium":[("SYN",0.4),("FIN",0.15),("UDP_SWEEP",0.1),("SSH_BRUTE",0.1)],
        "high":[("SYN",0.35),("FIN",0.15),("NULL",0.1),("XMAS",0.1),("AGGRESSIVE",0.15),("UDP_SWEEP",0.1)],
        "extreme":[("AGGRESSIVE",0.4),("SYN",0.2),("UDP_SWEEP",0.15),("DOS",0.15)]
    }[INTENSITY]

    pool=[]
    for k,w in weights: pool.extend([k]*int(max(1,w*100)))

    events = {"low":1,"medium":3,"high":8,"extreme":50}[INTENSITY]
    if BURST_MODE: events=max(events,BURST_SIZE)

    for _ in range(events):
        choice=random.choice(pool)
        if choice=="AGGRESSIVE":
            msgs.extend(generate_aggressive_sequence(port_count=random.randint(20,60)))
        elif choice=="UDP_SWEEP":
            msgs.extend(generate_udp_sweep(ports=random.randint(10,40)))
        elif choice=="ICMP_SWEEP":
            msgs.extend(generate_icmp_sweep(count=random.randint(5,20)))
        elif choice=="SSH_BRUTE":
            msgs.extend(generate_ssh_brute(attempts=random.randint(2,8)))
        elif choice=="DOS":
            for _ in range(random.randint(1,5)): msgs.append(generate_scan_event("DOS"))
        else:
            msgs.append(generate_scan_event(choice))
    return msgs

# ----------------------------
# Worker
# ----------------------------
def worker_loop(thread_id:int):
    base_delay = INTENSITY_MAP.get(INTENSITY,0.5)
    while True:
        msgs = orchestrate_once()
        for m in msgs:
            print(m)
            try: send_syslog(m)
            except: pass
            time.sleep(base_delay if not BURST_MODE else (base_delay/10))
        jitter = random.uniform(0, base_delay)
        time.sleep(base_delay+jitter)

# ----------------------------
# Entry Point
# ----------------------------
def start():
    print("🔥 Cisco Professional Attack Syslog Generator Started")
    print(f"SIEM -> {SIEM_IP}:{SIEM_PORT}  TCP={USE_TCP}  INTENSITY={INTENSITY}  BURST={BURST_MODE}")
    threads=max(1,THREADS)
    for i in range(threads):
        t=threading.Thread(target=worker_loop,args=(i+1,),daemon=True)
        t.start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("Stopped by user")

if __name__=="__main__":
    start()
