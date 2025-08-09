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

    def get_peers(self):
        with self._lock:
            return self._state.get("peers", [])

    def set_volume_lock(self, volume_name: str, lock_data: dict):
        with self._lock:
            if "volumes" not in self._state:
                self._state["volumes"] = {}
            if volume_name not in self._state["volumes"]:
                # Handle case where volume is not yet in state
                return
            self._state["volumes"][volume_name]["lock"] = lock_data
            self._save_to_disk()

    def acquire_lock(self, vol_name, term, candidate):
        with self._lock:
            current_state = self._state.get("volumes", {}).get(vol_name, {})
            current_term = current_state.get("term", 0)
            lock = current_state.get("lock")

            if term <= current_term:
                return {"Err": f"Term {term} is not greater than current term {current_term}"}

            if lock and lock.get("term", 0) > term:
                return {"Err": f"A lock with a higher term {lock['term']} already exists"}

            self._state.setdefault("volumes", {}).setdefault(vol_name, {})
            self._state["volumes"][vol_name]["lock"] = {"term": term, "candidate": candidate}
            self._save_to_disk()
            return {"Err": ""}

    def commit_state(self, vol_name, term, active_node):
        with self._lock:
            current_state = self._state.get("volumes", {}).get(vol_name, {})
            current_term = current_state.get("term", 0)

            if term < current_term:
                return {"Err": f"Term {term} is less than current term {current_term}"}

            self._state.setdefault("volumes", {}).setdefault(vol_name, {})
            self._state["volumes"][vol_name]["active_node"] = active_node
            self._state["volumes"][vol_name]["term"] = term
            self._state["volumes"][vol_name]["lock"] = None
            self._save_to_disk()
            return {"Err": ""}

    def abort_promotion(self, vol_name, term, candidate):
        with self._lock:
            current_state = self._state.get("volumes", {}).get(vol_name, {})
            lock = current_state.get("lock")

            if not lock:
                return {"Err": ""}  # Already unlocked

            if lock.get("term") == term and lock.get("candidate") == candidate:
                self._state["volumes"][vol_name]["lock"] = None
                self._save_to_disk()

            return {"Err": ""}

    def _save_to_disk(self):
        # This private method MUST be called from within a locked section
        with self._state_file.open('w') as f:
            json.dump(self._state, f, indent=2)
