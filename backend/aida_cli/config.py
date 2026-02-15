import os
import json
from typing import Dict, Any, Optional

import sys

DEFAULT_CONFIG = {
    "llm": {
        "base_url": "https://api.openai.com/v1",
        "api_key": "",
        "model": "gpt-4o"
    },
    "mcp": {
        "transport": "http",
        "url": "http://127.0.0.1:8765/mcp",
        "command": [sys.executable, "-m", "aida_cli.mcp_stdio_server", "--project", "."],
        "working_directory": "."
    }
}

class Config:
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._get_default_config_path()
        self.data = self._load()

    def _get_default_config_path(self) -> str:
        home = os.path.expanduser("~")
        return os.path.join(home, ".aida", "config.json")

    def _load(self) -> Dict[str, Any]:
        if not os.path.exists(self.config_path):
            return DEFAULT_CONFIG.copy()
        try:
            with open(self.config_path, 'r') as f:
                loaded = json.load(f)
                # Merge with default to ensure all keys exist
                merged = DEFAULT_CONFIG.copy()
                self._deep_merge(merged, loaded)
                return merged
        except Exception as e:
            print(f"Warning: Failed to load config from {self.config_path}: {e}")
            return DEFAULT_CONFIG.copy()

    def _deep_merge(self, base: Dict, update: Dict):
        for k, v in update.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                self._deep_merge(base[k], v)
            else:
                base[k] = v

    def save(self):
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(self.data, f, indent=2)
        print(f"Configuration saved to {self.config_path}")

    @property
    def llm(self) -> Dict[str, Any]:
        return self.data.get("llm", {})

    @property
    def mcp(self) -> Dict[str, Any]:
        return self.data.get("mcp", {})

    # Env var overrides
    def get_llm_api_key(self) -> str:
        return os.environ.get("AIDA_LLM_KEY") or self.llm.get("api_key")

    def get_llm_base_url(self) -> str:
        return os.environ.get("AIDA_LLM_URL") or self.llm.get("base_url")

    def get_llm_model(self) -> str:
        return os.environ.get("AIDA_LLM_MODEL") or self.llm.get("model")
