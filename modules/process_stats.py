# modules/process_stats.py


class ProcessStats:
    def __init__(self, pid):
        self.pid = pid

    def get_process_name(self):
        try:
            with open(f"/proc/{self.pid}/comm", "r") as f:
                process_name = f.read().strip()
                return process_name
        except Exception as e:
            print(f"Error retrieving process name: {e}")
            return None

    def display_process_info(self):
        process_name = self.get_process_name()
        if process_name:
            print(f"Process Name: {process_name}")
        else:
            print("Unable to retrieve process name.")
