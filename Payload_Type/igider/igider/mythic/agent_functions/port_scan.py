from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *

class PortScanArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="ip_range",
                type=ParameterType.String,
                description="IP range to scan (e.g., 192.168.1.1-192.168.1.10)",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="port_range",
                type=ParameterType.String,
                description="Port range to scan (e.g., 80-100)",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="timeout",
                type=ParameterType.Number,
                description="Connection timeout in seconds",
                default_value=1,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
        ]

    async def parse_arguments(self):
        if not self.command_line:
            raise Exception("Require IP and port range.\n\tUsage: {}".format(PortScanCommand.help_cmd))
        try:
            args = json.loads(self.command_line) if self.command_line[0] == "{" else {"ip_range": "", "port_range": ""}
            if "ip_range" in args and "port_range" in args:
                self.args[0].value = args["ip_range"]
                self.args[1].value = args["port_range"]
                if "timeout" in args:
                    self.args[2].value = args["timeout"]
            else:
                parts = self.command_line.split()
                if len(parts) >= 2:
                    self.args[0].value = parts[0]
                    self.args[1].value = parts[1]
                    if len(parts) == 3:
                        self.args[2].value = float(parts[2])
                else:
                    raise Exception("Invalid arguments.")
        except Exception as e:
            raise Exception(f"Error parsing arguments: {str(e)}")

class PortScanCommand(CommandBase):
    cmd = "port_scan"
    needs_admin = False
    help_cmd = "port_scan <ip_range> <port_range> [timeout]"
    description = "Scan a range of IPs and ports to identify open ports and collect banners."
    version = 1
    supported_ui_features = ["network_scan"]
    is_download_file = False
    author = "@pentester"
    parameters = []
    attackmapping = ["T1046", "T1595"]
    argument_class = PortScanArguments
    browser_script = BrowserScript(script_name="port_scan", author="@pentester", for_new_ui=True)
    attributes = CommandAttributes(
        supported_python_versions=["Python 3.8"],
        supported_os=[SupportedOS.MacOS, SupportedOS.Windows, SupportedOS.Linux],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        ip_range = taskData.args.get_arg("ip_range")
        port_range = taskData.args.get_arg("port_range")
        timeout = taskData.args.get_arg("timeout")
        response.DisplayParams = f"Scanning {ip_range} ports {port_range} with timeout {timeout}s"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp