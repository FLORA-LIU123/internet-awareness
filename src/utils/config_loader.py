import os
from pathlib import Path
from typing import Any, Dict, List

import yaml


class Config:
    _instance: "Config | None" = None

    def __init__(self, settings_path: str = "config/settings.yaml",
                 targets_path: str = "config/targets.yaml") -> None:
        self._settings: Dict[str, Any] = {}
        self._targets: List[Dict[str, Any]] = []
        self._settings_path = settings_path
        self._targets_path = targets_path
        self.reload()

    @classmethod
    def get(cls) -> "Config":
        if cls._instance is None:
            cls._instance = Config()
        return cls._instance

    def reload(self) -> None:
        base = Path(__file__).resolve().parents[2]
        with open(base / self._settings_path, encoding="utf-8") as f:
            self._settings = yaml.safe_load(f) or {}
        with open(base / self._targets_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            self._targets = data.get("targets", [])

        # Allow env-var override for the OTX API key
        otx_key = os.environ.get("OTX_API_KEY", "")
        if otx_key:
            self._settings.setdefault("threat_intel", {})["otx_api_key"] = otx_key

    def get_setting(self, *keys: str, default: Any = None) -> Any:
        node = self._settings
        for k in keys:
            if not isinstance(node, dict):
                return default
            if k not in node:
                return default
            node = node[k]
        return node

    @property
    def base_path(self) -> Path:
        """Project root directory (absolute)."""
        return Path(__file__).resolve().parents[2]

    @property
    def targets(self) -> List[Dict[str, Any]]:
        return [t for t in self._targets if t.get("enabled", True)]

    @property
    def db_path(self) -> str:
        return self.get_setting("database", "path", default="data/awareness.db")

    @property
    def weights(self) -> Dict[str, float]:
        return self.get_setting("scoring", "weights", default={
            "availability": 0.4,
            "response_time": 0.3,
            "link_connectivity": 0.2,
            "security_risk": 0.1,
        })

    def save_settings(self, new_settings: Dict[str, Any]) -> None:
        base = Path(__file__).resolve().parents[2]
        path = base / self._settings_path
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(new_settings, f, allow_unicode=True, default_flow_style=False)
        self._settings = new_settings

    def save_targets(self, new_targets: List[Dict[str, Any]]) -> None:
        base = Path(__file__).resolve().parents[2]
        path = base / self._targets_path
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump({"targets": new_targets}, f, allow_unicode=True, default_flow_style=False)
        self._targets = new_targets
