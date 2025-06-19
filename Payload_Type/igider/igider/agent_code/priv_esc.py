    import json
    import os
    import platform
    import subprocess
    import stat
    from datetime import datetime
    import pwd
    import grp
    import getpass
    import logging

    class PrivEsc:
        def __init__(self):
            # Initialize logging (customize based on agent's logging setup)
            self.logger = logging.getLogger("PrivEsc")
            self.logger.setLevel(logging.DEBUG)

        def priv_esc(self, task_id, checks="all", sudo_password=None):
            """
            Perform privilege escalation checks on the current system
            """
            self.logger.debug(f"Starting priv_esc task {task_id} with checks={checks}, sudo_password={'[REDACTED]' if sudo_password else None}")
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
                self.logger.debug(f"Initialized results: {results}")

                # Select checks based on input
                check_functions = {
                    "file_permissions": self._check_file_permissions,
                    "sudo_rights": self._check_sudo_rights,
                    "system_info": self._check_system_info,
                    "cron_jobs": self._check_cron_jobs,
                    "service_configs": self._check_service_configs
                }
                self.logger.debug(f"Available check functions: {list(check_functions.keys())}")

                selected_checks = check_functions.keys() if checks == "all" else checks.split(",")
                self.logger.debug(f"Selected checks: {selected_checks}")

                # Run selected checks
                for check in selected_checks:
                    if check in check_functions:
                        self.logger.debug(f"Executing check: {check}")
                        if [task for task in self.taskings if task["task_id"] == task_id][0]["stopped"]:
                            results["status"] = "stopped"
                            self.logger.warning(f"Task {task_id} stopped during {check} check")
                            break
                        results["vulnerabilities"].extend(check_functions[check](sudo_password))
                        results["summary"]["checks_performed"] += 1
                        self._send_intermediate_results(task_id, check, results["vulnerabilities"])
                    else:
                        self.logger.error(f"Unknown check type: {check}")
                
                results["summary"]["potential_vulns"] = len(results["vulnerabilities"])
                results["scan_end"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.logger.debug(f"Completed priv_esc task {task_id}, results: {results}")
                return json.dumps(results)
                
            except Exception as e:
                self.logger.error(f"Exception in priv_esc: {str(e)}", exc_info=True)
                return json.dumps({"error": f"Privilege escalation check failed: {str(e)}"})

        def _check_file_permissions(self, sudo_password):
            """Check for world-writable files and sensitive file permissions"""
            self.logger.debug("Starting file_permissions check")
            vulnerabilities = []
            system = platform.system()
            self.logger.debug(f"System detected: {system}")

            if system in ["Linux", "Darwin"]:
                sensitive_paths = [
                    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
                    "/root/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys"
                ]
                for path in sensitive_paths:
                    try:
                        if "*" in path:
                            import glob
                            files = glob.glob(path)
                        else:
                            files = [path]
                        self.logger.debug(f"Checking path: {path}, files: {files}")
                        for file_path in files:
                            if os.path.exists(file_path):
                                st = os.stat(file_path)
                                mode = st.st_mode
                                if mode & stat.S_IWOTH:
                                    vulnerabilities.append({
                                        "type": "file_permission",
                                        "path": file_path,
                                        "details": "World-writable file detected",
                                        "severity": "high"
                                    })
                                    self.logger.warning(f"Found world-writable file: {file_path}")
                                elif mode & stat.S_IWGRP and "shadow" in file_path:
                                    vulnerabilities.append({
                                        "type": "file_permission",
                                        "path": file_path,
                                        "details": "Group-writable sensitive file",
                                        "severity": "critical"
                                    })
                                    self.logger.warning(f"Found group-writable shadow file: {file_path}")
                    except Exception as e:
                        self.logger.error(f"Error checking {file_path}: {str(e)}")
                        vulnerabilities.append({
                            "type": "file_permission",
                            "path": file_path,
                            "details": f"Error checking permissions: {str(e)}",
                            "severity": "info"
                        })

            elif system == "Windows":
                try:
                    cmd = "sc query state= all"
                    output = subprocess.check_output(cmd, shell=True, text=True)
                    self.logger.debug("Checking Windows services")
                    for line in output.splitlines():
                        if "SERVICE_NAME" in line:
                            service = line.split(":")[1].strip()
                            vulnerabilities.append({
                                "type": "service_permission",
                                "path": service,
                                "details": "Service found, check permissions manually",
                                "severity": "medium"
                            })
                            self.logger.info(f"Found service: {service}")
                except Exception as e:
                    self.logger.error(f"Error checking Windows services: {str(e)}")
                    vulnerabilities.append({
                        "type": "service_permission",
                        "details": f"Error checking services: {str(e)}",
                        "severity": "info"
                    })

            self.logger.debug(f"Completed file_permissions check, found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities

        def _check_sudo_rights(self, sudo_password):
            """Check for sudo privileges without password or with provided password"""
            self.logger.debug("Starting sudo_rights check")
            vulnerabilities = []
            if platform.system() in ["Linux", "Darwin"]:
                try:
                    cmd = "sudo -l" if not sudo_password else f"echo {sudo_password} | sudo -S -l"
                    self.logger.debug(f"Executing sudo command: {cmd}")
                    output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
                    if "(ALL) NOPASSWD" in output:
                        vulnerabilities.append({
                            "type": "sudo_rights",
                            "details": "User has NOPASSWD sudo privileges",
                            "severity": "critical"
                        })
                        self.logger.warning("Detected NOPASSWD sudo privileges")
                    elif "ALL" in output:
                        vulnerabilities.append({
                            "type": "sudo_rights",
                            "details": "User has sudo privileges",
                            "severity": "high"
                        })
                        self.logger.info("Detected sudo privileges")
                except subprocess.CalledProcessError as e:
                    self.logger.error(f"Sudo check failed: {str(e)}")
                    vulnerabilities.append({
                        "type": "sudo_rights",
                        "details": f"Sudo check failed: {str(e)}",
                        "severity": "info"
                    })
            self.logger.debug(f"Completed sudo_rights check, found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities

        def _check_system_info(self, sudo_password):
            """Gather system information for potential escalation vectors"""
            self.logger.debug("Starting system_info check")
            vulnerabilities = []
            system = platform.system()
            
            if system in ["Linux", "Darwin"]:
                try:
                    kernel = os.uname().release
                    self.logger.debug(f"Kernel version: {kernel}")
                    if "2.6" in kernel or "3." in kernel:
                        vulnerabilities.append({
                            "type": "kernel_version",
                            "details": f"Potentially vulnerable kernel version: {kernel}",
                            "severity": "medium"
                        })
                        self.logger.warning(f"Potentially vulnerable kernel: {kernel}")
                    
                    if os.access("/etc/passwd", os.W_OK):
                        vulnerabilities.append({
                            "type": "system_config",
                            "path": "/etc/passwd",
                            "details": "Writable /etc/passwd detected",
                            "severity": "critical"
                        })
                        self.logger.warning("/etc/passwd is writable")
                except Exception as e:
                    self.logger.error(f"Error checking system info: {str(e)}")
                    vulnerabilities.append({
                        "type": "system_info",
                        "details": f"Error checking system info: {str(e)}",
                        "severity": "info"
                    })
            
            self.logger.debug(f"Completed system_info check, found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities

        def _check_cron_jobs(self, sudo_password):
            """Check for misconfigured cron jobs"""
            self.logger.debug("Starting cron_jobs check")
            vulnerabilities = []
            if platform.system() in ["Linux", "Darwin"]:
                cron_paths = ["/etc/crontab", "/etc/cron.d/*", "/var/spool/cron/*"]
                try:
                    for path in cron_paths:
                        import glob
                        files = glob.glob(path)
                        self.logger.debug(f"Checking cron path: {path}, files: {files}")
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
                                    self.logger.warning(f"Found world-writable cron job: {file_path}")
                except Exception as e:
                    self.logger.error(f"Error checking cron jobs: {str(e)}")
                    vulnerabilities.append({
                        "type": "cron_job",
                        "details": f"Error checking cron jobs: {str(e)}",
                        "severity": "info"
                    })
            self.logger.debug(f"Completed cron_jobs check, found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities

        def _check_service_configs(self, sudo_password):
            """Check for misconfigured services"""
            self.logger.debug("Starting service_configs check")
            vulnerabilities = []
            if platform.system() in ["Linux", "Darwin"]:
                try:
                    cmd = "ps aux | grep root"
                    output = subprocess.check_output(cmd, shell=True, text=True)
                    self.logger.debug("Checking services running as root")
                    for line in output.splitlines():
                        if "root" in line and not any(x in line for x in ["ps aux", "grep root"]):
                            vulnerabilities.append({
                                "type": "service_config",
                                "details": f"Service running as root: {line.split()[10:]}",
                                "severity": "medium"
                            })
                            self.logger.info(f"Found service running as root: {line.split()[10:]}")
                except Exception as e:
                    self.logger.error(f"Error checking services: {str(e)}")
                    vulnerabilities.append({
                        "type": "service_config",
                        "details": f"Error checking services: {str(e)}",
                        "severity": "info"
                    })
            self.logger.debug(f"Completed service_configs check, found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities

        def _send_intermediate_results(self, task_id, check_type, vulnerabilities):
            """Send intermediate privilege escalation check results"""
            self.logger.debug(f"Sending intermediate results for {check_type} check")
            data = {
                "action": "post_response",
                "responses": [{
                    "task_id": task_id,
                    "user_output": f"Completed {check_type} check: {len(vulnerabilities)} potential vulnerabilities found",
                    "completed": False
                }]
            }
            self.postMessageAndRetrieveResponse(data)