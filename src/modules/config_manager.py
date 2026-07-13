"""
config_manager.py
Gestión de la configuración persistente de Scanner PRV.
"""

import json
import os

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "config", "config.json")

DEFAULT_CONFIG = {
    "tema": "verde",
    "idioma": "es",
    "puertos_por_defecto": "21,22,23,25,53,80,110,143,443,445,3306,3389,8080",
    "ubicacion_reportes": "reportes",
    "banner_texto": "Scanner PRV",
    "auto_guardar_historial": True
}


class ConfigManager:
    def __init__(self, path=CONFIG_PATH):
        self.path = path
        self.config = self._cargar()

    def _cargar(self):
        if not os.path.exists(self.path):
            self._guardar(DEFAULT_CONFIG)
            return DEFAULT_CONFIG.copy()
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            merged = DEFAULT_CONFIG.copy()
            merged.update(data)
            return merged
        except (json.JSONDecodeError, OSError):
            return DEFAULT_CONFIG.copy()

    def _guardar(self, data):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

    def get(self, clave):
        return self.config.get(clave)

    def set(self, clave, valor):
        self.config[clave] = valor
        self._guardar(self.config)

    def restaurar_por_defecto(self):
        self.config = DEFAULT_CONFIG.copy()
        self._guardar(self.config)
