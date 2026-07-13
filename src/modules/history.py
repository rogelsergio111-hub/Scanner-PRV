"""
history.py
Guarda y consulta el historial de auditorías realizadas con Scanner PRV.
"""

import json
import os
from datetime import datetime

HISTORIAL_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "historial", "historial.json")


def _cargar():
    if not os.path.exists(HISTORIAL_PATH):
        return []
    try:
        with open(HISTORIAL_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def _guardar(datos):
    os.makedirs(os.path.dirname(HISTORIAL_PATH), exist_ok=True)
    with open(HISTORIAL_PATH, "w", encoding="utf-8") as f:
        json.dump(datos, f, indent=4, ensure_ascii=False)


def registrar_escaneo(info_host, analisis_seguridad, tipo_escaneo):
    historial = _cargar()
    entrada = {
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tipo_escaneo": tipo_escaneo,
        "ip": info_host["ip"],
        "hostname": info_host["hostname"],
        "puertos_abiertos": len([p for p in info_host["puertos"] if p["estado"] == "open"]),
        "nivel_seguridad": analisis_seguridad["puntaje"],
        "estado_seguridad": analisis_seguridad["estado"],
    }
    historial.append(entrada)
    _guardar(historial)
    return entrada


def obtener_historial():
    return _cargar()


def limpiar_historial():
    _guardar([])
