    import json
    import os
    import platform
    import subprocess
    import stat
    from datetime import datetime
    import pwd
    import grp
    import getpass

    class PrivEsc:
        def priv_esc(self, task_id, checks="all", sudo_password=None):
            """
            Perform privilege escalation checks on the current system
            """
            try:
                # Initialize results
                results = {
                    "scan_start": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "system": platform.system(),
                    "hostname": platform.node(),
                    "current_user": getpass.getuser(),
                    "vulnerabilities": [],
                    "summary": {"checks_performed": 0, "potential_vulns": 0},
                    "status": "completed"
                }

                # Select checks based on input
                check_functions = {
                    "file_permissions": self._check_file_permissions,
                    "sudo_rights": self._check_sudo_rights,
                    "system_info": self._check_system_info,
                    "cron_jobs": self._check_cron_jobs,
                    "service_configs": self._check_service_configs
                }

                selected_checks = check_functions.keys() if checks == "all" else checks.split(",")

                # Run selected checks
                for check in selected_checks:
                    if check in check_functions:
                        if [task for task in self.taskings if task["task_id"] == task_id][0]["stopped"]:
                            results["status"] = "stopped"
                            break
                        results["vulnerabilities"].extend(check_functions[check](sudo_password))
                        results["summary"]["checks_performed"] += 1
                        self._send_intermediate_results(task_id, check, results["vulnerabilities"])
                
                results["summary"]["potential_vulns"] = len(results["vulnerabilities"])
                results["scan_end"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                return json.dumps(results)

            except Exception as e:
                return json.dumps({"error": f"Privilege escalation check failed: {str(e)}"})

        def _check_file_permissions(self, sudo_password):
            """Check for world-writable files and sensitive file permissions"""
            vulnerabilities = []
            system = platform.system()

            if system in ["Linux", "Darwin"]:  # Linux or macOS
                sensitive_paths = [
                    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
                    "/root/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys"
                ]
                for path in sensitive_paths:
                    try:
                        # Handle wildcard paths
                        if "*" in path:
                            import glob
                            files = glob.glob(path)
                        else:
                            files = [path]

                        for file_path in files:
                            if os.path.exists(file_path):
                                st = os.stat(file_path)
                                mode = st.st_mode
                                if mode & stat.S_IWOTH:  # World-writable
                                    vulnerabilities.append({
                                        "type": "file_permission",
                                        "path": file_path,
                                        "details": "World-writable file detected",
                                        "severity": "high"
                                    })
                                elif mode & stat.S_IWGRP and "shadow" in file_path:  # Group-writable shadow
                                    vulnerabilities.append({
                                        "type": "file_permission",
                                        "path": file_path,
                                        "details": "Group-writable sensitive file",
                                        "severity": "critical"
                                    })
                    except Exception as e:
                        vulnerabilities.append({
                            "type": "file_permission",
                            "path": file_path,
                            "details": f"Error checking permissions: {str(e)}",
                            "severity": "info"
                        })

            elif system == "Windows":
                # Check for weak service permissions
                try:
                    cmd = "sc query state= all"
                    output = subprocess.check_output(cmd, shell=True, text=True)
                    for line in output.splitlines():
                        if "SERVICE_NAME" in line:
                            service = line.split(":")[1].strip()
                            vulnerabilities.append({
                                "type": "service_permission",
                                "path": service,
                                "details": "Service found, check permissions manually",
                                "severity": "medium"
                            })
                except Exception as e:
                    vulnerabilities.append({
                        "type": "service_permission",
                        "details": f"Error checking services: {str(e)}",
                        "severity": "info"
                    })

            return vulnerabilities

        def _check_sudo_rights(self, sudo_password):
            """Check for sudo privileges without password or with provided password"""
            vulnerabilities = []
            if platform.system() in ["Linux", "Darwin"]:
                try:
                    cmd = "sudo -l" if not sudo_password else f"echo {sudo_password} | sudo -S -l"
                    output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
                    if "(ALL) NOPASSWD" in output:
                        vulnerabilities.append({
                            "type": "sudo_rights",
                            "details": "User has NOPASSWD sudo privileges",
                            "severity": "critical"
                        })
                    elif "ALL" in output:
                        vulnerabilities.append({
                            "type": "sudo_rights",
                            "details": "User has sudo privileges",
                            "severity": "high"
                        })
                except subprocess.CalledProcessError as e:
                    vulnerabilities.append({
                        "type": "sudo_rights",
                        "details": f"Sudo check failed: {str(e)}",
                        "severity": "info"
                    })
            return vulnerabilities

        def _check_system_info(self, sudo_password):
            """Gather system information for potential escalation vectors"""
            vulnerabilities = []
            system = platform.system()
            
            if system in ["Linux", "Darwin"]:
                try:
                    # Check kernel version
                    kernel = os.uname().release
                    if "2.6" in kernel or "3." in kernel:  # Old kernels
                        vulnerabilities.append({
                            "type": "kernel_version",
                            "details": f"Potentially vulnerable kernel version: {kernel}",
                            "severity": "medium"
                        })
                    
                    # Check for writable /etc/passwd
                    if os.access("/etc/passwd", os.W_OK):
                        vulnerabilities.append({
                            "type": "system_config",
                            "path": "/etc/passwd",
                            "details": "Writable /etc/passwd detected",
                            "severity": "critical"
                        })
                except Exception as e:
                    vulnerabilities.append({
                        "type": "system_info",
                        "details": f"Error checking system info: {str(e)}",
                        "severity": "info"
                    })
            
            return vulnerabilities

        def _check_cron_jobs(self, sudo_password):
            """Check for misconfigured cron jobs"""
            vulnerabilities = []
            if platform.system() in ["Linux", "Darwin"]:
                cron_paths = ["/etc/crontab", "/etc/cron.d/*", "/var/spool/cron/*"]
                try:
                    for path in cron_paths:
                        import glob
                        files = glob.glob(path)
                        for file_path in files:
                            if os.path.exists(file_path):
                                st = os.stat(file_path)
                                if st.st_mode & stat.S_IWOTH:
                                    vulnerabilities.append({
                                        "type": "cron_job",
                                        "path": file_path,
                                        "details": "World-writable cron job detected",
                                        "severity": "high"
                                    })
                except Exception as e:
                    vulnerabilities.append({
                        "type": "cron_job",
                        "details": f"Error checking cron jobs: {str(e)}",
                        "severity": "info"
                    })
            return vulnerabilities

        def _check_service_configs(self, sudo_password):
            """Check for misconfigured services"""
            vulnerabilities = []
            if platform.system() in ["Linux", "Darwin"]:
                try:
                    # Check for services running as root
                    cmd = "ps aux | grep root"
                    output = subprocess.check_output(cmd, shell=True, text=True)
                    for line in output.splitlines():
                        if "root" in line and not any(x in line for x in ["ps aux", "grep root"]):
                            vulnerabilities.append({
                                "type": "service_config",
                                "details": f"Service running as root: {line.split()[10:]}",
                                "severity": "medium"
                            })
                except Exception as e:
                    vulnerabilities.append({
                        "type": "service_config",
                        "details": f"Error checking services: {str(e)}",
                        "severity": "info"
                    })
            return vulnerabilities

        def _send_intermediate_results(self, task_id, check_type, vulnerabilities):
            """Send intermediate privilege escalation check results"""
            data = {
                "action": "post_response",
                "responses": [{
                    "task_id": task_id,
                    "user_output": f"Completed {check_type} check: {len(vulnerabilities)} potential vulnerabilities found",
                    "completed": False
                }]
            }
            self.postMessageAndRetrieveResponse(data)