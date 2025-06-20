from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *

class PrivescArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass  # No arguments required for privesc

class PrivescCommand(CommandBase):
    cmd = "privesc"
    needs_admin = False
    help_cmd = "privesc"
    description = "Perform privilege escalation checks on the target system (e.g., sudo rights, writable system files)."
    version = 1
    supported_ui_features = ["privesc:check"]
    is_download_file = False
    author = "@ajpc500"
    parameters = []
    attackmapping = ["T1068", "T1548"]
    argument_class = PrivescArguments
    browser_script = BrowserScript(script_name="privesc", author="@ajpc500", for_new_ui=True)
    attributes = CommandAttributes(
        supported_python_versions=["Python 2.7", "Python 3.8"],
        supported_os=[SupportedOS.Linux],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = "Running privilege escalation checks"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp