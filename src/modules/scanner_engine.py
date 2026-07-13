"""
scanner_engine.py
Capa sobre python-nmap que ejecuta los distintos tipos de escaneo
y normaliza los resultados en estructuras simples de usar.
"""

import os
import shutil
import time

try:
    import nmap
except ImportError:
    nmap = None


class ScannerEngineError(Exception):
    pass


def tiene_privilegios_admin():
    """True si el proceso corre como root (Linux/Mac) o Administrador (Windows)."""
    if os.name == "nt":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


class ScannerEngine:
    """
    Envuelve python-nmap (que a su vez llama al binario nmap instalado
    en el sistema). Requiere tener nmap instalado en el equipo.
    """

    def __init__(self):
        if nmap is None:
            raise ScannerEngineError(
                "No se encontró la librería 'python-nmap'. Instálala con: pip install -r requirements.txt"
            )
        if shutil.which("nmap") is None:
            raise ScannerEngineError(
                "No se encontró el binario 'nmap' en el sistema.\n"
                "  Instálalo con: sudo apt install nmap  (Debian/Ubuntu)\n"
                "  o descárgalo desde https://nmap.org/download.html"
            )
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            raise ScannerEngineError(
                "No se pudo inicializar Nmap. Verifica que esté correctamente instalado."
            )

    # ------------------------------------------------------------------
    # Escaneos
    # ------------------------------------------------------------------
    def escaneo_rapido(self, objetivo, puertos_comunes):
        return self._ejecutar(objetivo, puertos_comunes, args="-sV -T4")

    def escaneo_completo(self, objetivo):
        return self._ejecutar(objetivo, "1-65535", args="-sV -T4")

    def escaneo_personalizado(self, objetivo, puertos):
        return self._ejecutar(objetivo, puertos, args="-sV -T4")

    def escaneo_rango_puertos(self, objetivo, inicio, fin):
        return self._ejecutar(objetivo, f"{inicio}-{fin}", args="-sV -T4")

    def deteccion_sistema_operativo(self, objetivo):
        # -O requiere privilegios de administrador/root
        if not tiene_privilegios_admin():
            raise ScannerEngineError(
                "La detección de sistema operativo (-O) requiere privilegios de administrador.\n"
                "  Linux/Mac: ejecuta con 'sudo'  ->  sudo venv/bin/python scanner.py\n"
                "  Windows: abre la terminal 'como Administrador'"
            )
        return self._ejecutar(objetivo, None, args="-O -T4", es_deteccion_so=True)

    def deteccion_servicios(self, objetivo, puertos):
        return self._ejecutar(objetivo, puertos, args="-sV -sC -T4")

    # ------------------------------------------------------------------
    def _ejecutar(self, objetivo, puertos, args, es_deteccion_so=False):
        inicio = time.time()
        try:
            if puertos:
                self.nm.scan(hosts=objetivo, ports=puertos, arguments=args)
            else:
                self.nm.scan(hosts=objetivo, arguments=args)
        except Exception as e:
            mensaje = str(e)
            if "root privileges" in mensaje.lower():
                raise ScannerEngineError(
                    "Nmap necesita privilegios de administrador para este tipo de escaneo.\n"
                    "  Linux/Mac: sudo venv/bin/python scanner.py\n"
                    "  Windows: ejecuta la terminal como Administrador"
                )
            raise ScannerEngineError(f"Error al ejecutar el escaneo: {mensaje}")

        duracion = round(time.time() - inicio, 2)

        if objetivo not in self.nm.all_hosts():
            # Puede que el nmap resuelva a otra IP (DNS)
            hosts = self.nm.all_hosts()
            if not hosts:
                return None
            host_key = hosts[0]
        else:
            host_key = objetivo

        return self._normalizar(host_key, duracion, es_deteccion_so)

    def _normalizar(self, host_key, duracion, es_deteccion_so=False):
        host = self.nm[host_key]

        info = {
            "ip": host_key,
            "hostname": host.hostname() or "Desconocido",
            "estado": host.state(),
            "mac": host["addresses"].get("mac", "No detectada"),
            "sistema_operativo": self._extraer_so(host, es_deteccion_so),
            "duracion_segundos": duracion,
            "puertos": [],
        }

        for proto in host.all_protocols():
            puertos = host[proto].keys()
            for puerto in sorted(puertos):
                datos = host[proto][puerto]
                info["puertos"].append({
                    "puerto": puerto,
                    "protocolo": proto,
                    "estado": datos.get("state", "desconocido"),
                    "servicio": datos.get("name", "desconocido"),
                    "version": (datos.get("product", "") + " " + datos.get("version", "")).strip() or "N/D",
                })

        return info

    @staticmethod
    def _extraer_so(host, es_deteccion_so=False):
        try:
            coincidencias = host.get("osmatch", [])
            if coincidencias:
                return coincidencias[0]["name"]
        except Exception:
            pass

        if es_deteccion_so:
            # Se ejecutó -O con privilegios, pero no hubo coincidencia:
            # normalmente porque no hay puertos abiertos/cerrados para
            # analizar la pila TCP/IP, o el host filtra las sondas.
            return "No detectado (nmap no encontró suficientes puertos abiertos/cerrados para identificar el SO)"
        return "No analizado (usa la opción 'Detección de sistema operativo')"
