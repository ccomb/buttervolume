import threading
import json
from pathlib import Path

class StateManager:
    def __init__(self, state_file_path: Path):
        self._lock = threading.Lock()
        self._state_file = state_file_path
        self._state = {}
        self.load()

    def load(self):
        with self._lock:
            if self._state_file.exists():
                with self._state_file.open('r') as f:
                    self._state = json.load(f)

    def get_volume_state(self, volume_name: str):
        with self._lock:
            return json.loads(json.dumps(self._state.get("volumes", {}).get(volume_name)))

    def set_volume_lock(self, volume_name: str, lock_data: dict):
        with self._lock:
            if "volumes" not in self._state:
                self._state["volumes"] = {}
            if volume_name not in self._state["volumes"]:
                # Handle case where volume is not yet in state
                return
            self._state["volumes"][volume_name]["lock"] = lock_data
            self._save_to_disk()

    def _save_to_disk(self):
        # This private method MUST be called from within a locked section
        with self._state_file.open('w') as f:
            json.dump(self._state, f, indent=2)
