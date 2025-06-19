from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

class PrivEscArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass  # No arguments required

class PrivEscCommand(CommandBase):
    cmd = "priv_esc"
    needs_admin = False
    help_cmd = "priv_esc"
    description = "Check for privilege escalation vectors on Linux systems."
    version = 1
    supported_ui_features = ["priv_esc"]
    is_download_file = False
    author = "@pentester"
    parameters = []
    attackmapping = ["T1069", "T1082"]
    argument_class = PrivEscArguments
    browser_script = BrowserScript(script_name="priv_esc", author="@pentester", for_new_ui=True)
    attributes = CommandAttributes(
        supported_python_versions=["Python 3.8"],
        supported_os=[SupportedOS.Linux],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = "Checking privilege escalation vectors..."
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp