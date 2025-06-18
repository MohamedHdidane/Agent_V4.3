from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

class DownloadArguments(TaskArguments):
    def __init__(self, task_id: str):
        super().__init__(task_id)
        self.add_arg(
            name="path",
            arg_type=MythicCommandBase.ArgumentType.String,
            description="Path to the file to download",
            parameter_group_info=[
                ParameterGroupInfo(
                    required=True,
                    ui_position=1,
                )
            ],
        )

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)
        else:
            raise ValueError("Missing arguments")


class DownloadCommand(MythicCommandBase):
    cmd = "download"
    needs_admin = False
    help_cmd = "download [path]"
    description = "Download a file from the target."
    version = 1
    author = "@med"
    argument_class = DownloadArguments
    attackmapping = ["T1020"]

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: str) -> PTTaskMessageResponse:
        resp = PTTaskMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp


