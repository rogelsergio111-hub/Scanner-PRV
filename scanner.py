#!/usr/bin/env python3
"""
Scanner PRV
-----------
Herramienta profesional de auditoría de redes construida sobre Nmap,
con enfoque educativo para estudiantes de redes y ciberseguridad.

Uso:
    python scanner.py

Requisitos:
    - Tener Nmap instalado en el sistema (https://nmap.org/download.html)
    - pip install -r requirements.txt
"""

import sys

from src.modules.app import ScannerPRVApp
from src.modules import ui


def main():
    try:
        app = ScannerPRVApp()
        app.iniciar()
    except KeyboardInterrupt:
        print()
        ui.mensaje_info("Saliendo de Scanner PRV...")
        sys.exit(0)


if __name__ == "__main__":
    main()
