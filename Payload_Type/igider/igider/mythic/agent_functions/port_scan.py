from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *


class PortScanArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="target", 
                type=ParameterType.String, 
                description="Target host/IP or IP range (e.g., 192.168.1.1, 192.168.1.1-10, 192.168.1.0/24)",
                parameter_group_info=[ParameterGroupInfo(
                    required=True
                )]
            ),
            CommandParameter(
                name="ports", 
                type=ParameterType.String, 
                description="Ports to scan (e.g., 80, 80-443, 21,22,80,443)",
                parameter_group_info=[ParameterGroupInfo(
                    required=True
                )]
            ),
            CommandParameter(
                name="timeout", 
                type=ParameterType.String, 
                description="Connection timeout in seconds (default: 1)",
                parameter_group_info=[ParameterGroupInfo(
                    required=False
                )],
                default_value="1"
            ),
            CommandParameter(
                name="threads", 
                type=ParameterType.String, 
                description="Maximum concurrent threads (default: 100)",
                parameter_group_info=[ParameterGroupInfo(
                    required=False
                )],
                default_value="100"
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Require target and ports to scan.\n\tUsage: {}".format(PortScanCommand.help_cmd))
        
        if self.command_line[0] == "{":
            # JSON input
            temp_json = json.loads(self.command_line)
            if "target" in temp_json:
                self.args[0].value = temp_json["target"]
            if "ports" in temp_json:
                self.args[1].value = temp_json["ports"]
            if "timeout" in temp_json:
                self.args[2].value = float(temp_json["timeout"])
            if "threads" in temp_json:
                self.args[3].value = int(temp_json["threads"])
        else:
            # Command line parsing
            parts = self.command_line.split()
            if len(parts) < 2:
                raise Exception("Require both target and ports.\n\tUsage: {}".format(PortScanCommand.help_cmd))
            
            self.args[0].value = parts[0]  # target
            self.args[1].value = parts[1]  # ports
            
            if len(parts) > 2:
                try:
                    self.args[2].value = parts[2]  # timeout as string, will convert later
                except Exception:
                    self.args[2].value = "1"
            if len(parts) > 3:
                try:
                    self.args[3].value = parts[3]  # threads as string, will convert later
                except Exception:
                    self.args[3].value = "100"


class PortScanCommand(CommandBase):
    cmd = "port_scan"
    needs_admin = False
    help_cmd = "port_scan [target] [ports] [timeout] [threads]"
    description = "Perform TCP port scan on target host(s). Supports single IPs, IP ranges, and CIDR notation."
    version = 1
    supported_ui_features = []
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_remove_file = False
    is_upload_file = False
    author = "@ajpc500"
    parameters = []
    attackmapping = ["T1046"]  # Network Service Scanning
    argument_class = PortScanArguments
    browser_script = BrowserScript(script_name="port_scan", author="@ajpc500", for_new_ui=True)
    attributes = CommandAttributes(
        supported_python_versions=["Python 2.7", "Python 3.8"],
        supported_os=[SupportedOS.MacOS, SupportedOS.Windows, SupportedOS.Linux],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        
        target = taskData.args.get_arg("target")
        ports = taskData.args.get_arg("ports")
        timeout_str = taskData.args.get_arg("timeout")
        threads_str = taskData.args.get_arg("threads")
        
        # Convert string parameters to numbers with validation
        try:
            timeout = float(timeout_str) if timeout_str else 1.0
        except (ValueError, TypeError):
            timeout = 1.0
            
        try:
            threads = int(threads_str) if threads_str else 100
        except (ValueError, TypeError):
            threads = 100
        
        response.DisplayParams = f"Target: {target}, Ports: {ports}, Timeout: {timeout}s, Threads: {threads}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp