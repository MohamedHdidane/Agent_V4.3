# igider/mythic/agent_functions/priv_esc.py
from mythic_container.MythicCommandBase import *
import json

class PrivEscArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="method",
                type=ParameterType.String,
                description="Method for privilege escalation",
                default_value="basic",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if self.command_line.strip().startswith("{"):
            temp_json = json.loads(self.command_line)
            self.load_args_from_json_string(json.dumps(temp_json))
        else:
            self.add_arg("method", self.command_line.strip())

class PrivEscCommand(CommandBase):
    cmd = "priv_esc"
    needs_admin = False
    help_cmd = "priv_esc [method]"
    description = "Attempt to escalate privileges using the specified method."
    version = 1
    author = "your_handle"
    argument_class = PrivEscArguments
    attackmapping = ["T1068", "T1548"]
    browser_script = BrowserScript(script_name="priv_esc", author="you", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS]
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        response.DisplayParams = f"Method: {taskData.args.get_arg('method')}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
