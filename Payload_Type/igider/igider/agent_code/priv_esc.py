import os
import json
import subprocess
import pwd
import stat

class PrivEsc:
    def __init__(self, current_directory):
        self.current_directory = current_directory
        self.taskings = []

    def check_suid(self):
        suid_files = []
        cmd = "find / -perm -4000 -type f 2>/dev/null"
        try:
            output = subprocess.check_output(cmd, shell=True, text=True)
            suid_files = output.strip().split('\n')
        except:
            pass
        return suid_files

    def check_writable_cron(self):
        cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.monthly", "/etc/cron.weekly"]
        writable_crons = []
        for cron_dir in cron_dirs:
            try:
                if os.access(cron_dir, os.W_OK):
                    writable_crons.append(cron_dir)
                for root, _, files in os.walk(cron_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if os.access(file_path, os.W_OK):
                            writable_crons.append(file_path)
            except:
                continue
        return writable_crons

    def check_sudo(self):
        try:
            output = subprocess.check_output(["sudo", "-l"], text=True, stderr=subprocess.PIPE)
            return output.strip().split('\n')
        except:
            return []

    def priv_esc(self, task_id):
        if [task for task in self.taskings if task["task_id"] == task_id][0]["stopped"]:
            return json.dumps({"status": "stopped", "results": []})
        results = {
            "current_user": pwd.getpwuid(os.getuid()).pw_name,
            "suid_binaries": self.check_suid(),
            "writable_cron": self.check_writable_cron(),
            "sudo_permissions": self.check_sudo()
        }
        return json.dumps({
            "status": "completed",
            "results": results
        })
    }
}