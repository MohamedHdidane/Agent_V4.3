from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *

class PrivEscArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="checks", 
                type=ParameterType.String, 
                description="Comma-separated list of checks to perform (file_permissions,sudo_rights,system_info,cron_jobs,service_configs) or 'all'",
                parameter_group_info=[ParameterGroupInfo(
                    ui_position=1,
                    required=False
                )],
                default_value="all"
            ),
            CommandParameter(
                name="sudo_password", 
                type=ParameterType.String, 
                description="Sudo password for privilege checks (optional)",
                parameter_group_info=[ParameterGroupInfo(
                    ui_position=2,
                    required=False
                )]
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            self.add_arg("checks", "all")
            return
        
        if self.command_line[0] == "{":
            # JSON input
            temp_json = json.loads(self.command_line)
            if "checks" in temp_json:
                self.add_arg("checks", temp_json["checks"])
            if "sudo_password" in temp_json:
                self.add_arg("sudo_password", temp_json["sudo_password"])
        else:
            # Split command line and handle quoted arguments
            parts = []
            current_part = ""
            in_quotes = False
            quote_char = None
            
            for char in self.command_line:
                if char in ['"', "'"] and not in_quotes:
                    in_quotes = True
                    quote_char = char
                elif char == quote_char and in_quotes:
                    in_quotes = False
                    quote_char = None
                elif char == ' ' and not in_quotes:
                    if current_part:
                        parts.append(current_part)
                        current_part = ""
                else:
                    current_part += char
            
            if current_part:
                parts.append(current_part)
            
            if len(parts) >= 1:
                self.add_arg("checks", parts[0])
            
            if len(parts) >= 2:
                self.add_arg("sudo_password", parts[1])

class PrivEscCommand(CommandBase):
    cmd = "priv_esc"
    needs_admin = False
    help_cmd = "priv_esc [checks] [sudo_password]"
    description = "Perform privilege escalation checks on the target system. Supports multiple check types and optional sudo password."
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
    attackmapping = ["T1068"]  # Exploitation for Privilege Escalation
    argument_class = PrivEscArguments
    browser_script = BrowserScript(script_name="priv_esc", author="@ajpc500", for_new_ui=True)
    attributes = CommandAttributes(
        supported_python_versions=["Python 2.7", "Python 3.8"],
        supported_os=[SupportedOS.MacOS, SupportedOS.Windows, SupportedOS.Linux],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        
        checks = taskData.args.get_arg("checks")
        sudo_password = taskData.args.get_arg("sudo_password")
        
        display_params = f"Checks: {checks}"
        if sudo_password:
            display_params += ", Sudo Password: [REDACTED]"
            
        response.DisplayParams = display_params
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp