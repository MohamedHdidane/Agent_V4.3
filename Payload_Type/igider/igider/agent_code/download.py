import os

def download(task_id, path):
    try:
        if not os.path.exists(path):
            return f"Error: File not found at {path}"

        with open(path, "rb") as f:
            file_content = f.read()

        # In a real scenario, you would send this to the C2 server
        # For now, we'll just return a success message and the size
        return f"Successfully read {len(file_content)} bytes from {path} for download."

    except Exception as e:
        return f"Error downloading file: {str(e)}"


