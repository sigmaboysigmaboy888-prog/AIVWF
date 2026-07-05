"""
Configuration handler using YAML file.
Creates config.yaml on first run, prompts for API key, enforces file permissions.
"""
import os
import stat
import yaml
from pathlib import Path
from getpass import getpass
from typing import Any, Dict

DEFAULT_CONFIG = {
    'api_key': 'AQ.Ab8RN6JES3dzmRqUfRiAIPsX-2yiY0FAqdsXpCTpoFi2gq3R4g',
    'api_base': 'https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent',
    'model': 'gemini-3.5-flash',
    'ai_provider': 'google',   # google or openai_compatible
    'concurrency': 10,
    'timeout': 15,
    'user_agent': 'AIVWF/1.0',
    'history_limit': 100,
    'scan_depth': 1,
    'prompt_file': 'prompts/default_analysis.prompt',
    'custom_prompt_file': 'prompts/custom.prompt',
}

CONFIG_PATH = Path('config.yaml')


class Config:
    def __init__(self, path: Path = CONFIG_PATH):
        self.path = path
        self.config: Dict[str, Any] = {}

    def initialize(self):
        """Create config if not exists, prompt for API key, set permissions."""
        if not self.path.exists():
            self.config = DEFAULT_CONFIG.copy()
            print("First run: please enter your Google AI API key (press Enter to skip).")
            api_key = getpass("API key: ").strip()
            if api_key:
                self.config['api_key'] = api_key
            self.save()
            print(f"Configuration saved to {self.path}")
        else:
            self.load()
        # Ensure strict permissions
        self._restrict_permissions()

    def load(self):
        with open(self.path, 'r') as f:
            self.config = yaml.safe_load(f) or {}
        # Merge missing defaults
        for key, value in DEFAULT_CONFIG.items():
            if key not in self.config:
                self.config[key] = value

    def save(self):
        with open(self.path, 'w') as f:
            yaml.safe_dump(self.config, f)
        self._restrict_permissions()

    def _restrict_permissions(self):
        try:
            os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass

    def get(self, key: str, default=None):
        return self.config.get(key, default)

    def set(self, key: str, value):
        self.config[key] = value

    def __getitem__(self, key):
        return self.config[key]

    def __setitem__(self, key, value):
        self.config[key] = value
