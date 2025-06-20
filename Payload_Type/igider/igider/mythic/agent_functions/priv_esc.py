from mythic_container.MythicCommandBase import *

class PrivEscCommand(CommandBase):
    cmd = "privesc"
    needs_admin = False
    help_cmd = "privesc"
    description = "Enumerate potential privilege escalation paths."
    version = 1
    author = "Kali GPT"
    argument_class = ArgumentNotRequired

    async def create_go_tasking(self, taskData):
        return PTTaskCreateTaskingMessageResponse(Success=True, TaskID=taskData.Task.ID)

    async def process_response(self, task, response):
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)