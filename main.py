import os
import sys
import subprocess
import socket
import uuid
import re
import requests

blacklisted_ips = ['']
blacklisted_macs = ['']
blacklisted_hwids = ['']
blacklisted_gpus = ['VirtualBox Graphics Adapter', 'VMware SVGA II']

def get_system_info():
    ip_address = socket.gethostbyname(socket.gethostname())
    mac_address = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
    hwid = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
    gpu_info = subprocess.check_output("wmic path win32_videocontroller get caption").decode()
    gpu = [gpu.strip() for gpu in gpu_info.splitlines()[1:] if gpu.strip()][0] if gpu_info else "Unknown GPU"
    return ip_address, mac_address, hwid, gpu

def detect_environment():
    vm_indicators = ['VBOX', 'VIRTUALBOX', 'VMWARE', 'XEN', 'QEMU', 'VIRTUAL', 'HYPERVISOR', 'SBOX', 'SANDBOX', 'CWSANDBOX']
    analysis_indicators = ['virustotal', 'hybrid-analysis', 'cuckoo', 'malwr', 'any.run', 'reverse.it', 'joe sandbox', 'threatgrid', 'cape sandbox', 'totalhash', 'intezer']
    output = subprocess.check_output('systeminfo').decode().upper()
    hostname = socket.gethostname().lower()
    username = os.getlogin().lower()
    for indicator in vm_indicators + analysis_indicators:
        if indicator in output or indicator in hostname or indicator in username:
            return True
    try:
        if requests.get('https://www.virustotal.com/').status_code == 200:
            return True
    except:
        pass
    return False

ip_address, mac_address, hwid, gpu = get_system_info()

if detect_environment() or ip_address in blacklisted_ips or mac_address in blacklisted_macs or hwid in blacklisted_hwids or gpu in blacklisted_gpus:
    sys.exit()
