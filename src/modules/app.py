"""
app.py
Controlador principal: dibuja el menú, recoge las opciones del usuario
y coordina el resto de módulos (escaneo, seguridad, reportes, historial).
"""

import os
import sys

from . import ui
from . import history
from . import reports
from . import learning_mode
from . import security_analysis
from .config_manager import ConfigManager
from .scanner_engine import ScannerEngine, ScannerEngineError

BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..")

OPCIONES_MENU = [
    ("1", "Escaneo rápido"),
    ("2", "Escaneo completo"),
    ("3", "Escaneo personalizado"),
    ("4", "Escaneo de rango de puertos"),
    ("5", "Detección de sistema operativo"),
    ("6", "Detección de servicios"),
    ("7", "Ver historial"),
    ("8", "Configuración"),
    ("9", "Modo aprendizaje (glosario)"),
    ("0", "Salir"),
]


class ScannerPRVApp:
    def __init__(self):
        self.config = ConfigManager()
        self.motor = None
        self.modo_aprendizaje = True

    # ------------------------------------------------------------------
    def iniciar(self):
        while True:
            ui.mostrar_banner(self.config.get("banner_texto"), self.config.get("tema"))
            self._mostrar_menu()
            opcion = ui.entrada("\nSelecciona una opción: ", self.config.get("tema")).strip()

            if opcion == "1":
                self._flujo_escaneo("rapido")
            elif opcion == "2":
                self._flujo_escaneo("completo")
            elif opcion == "3":
                self._flujo_escaneo("personalizado")
            elif opcion == "4":
                self._flujo_escaneo("rango")
            elif opcion == "5":
                self._flujo_escaneo("so")
            elif opcion == "6":
                self._flujo_escaneo("servicios")
            elif opcion == "7":
                self._ver_historial()
            elif opcion == "8":
                self._menu_configuracion()
            elif opcion == "9":
                self._toggle_modo_aprendizaje()
            elif opcion == "0":
                ui.mensaje_ok("¡Gracias por usar Scanner PRV!")
                sys.exit(0)
            else:
                ui.mensaje_error("Opción no válida.")
                ui.pausar()

    def _mostrar_menu(self):
        tema = self.config.get("tema")
        ui.titulo_seccion("MENÚ PRINCIPAL", tema)
        for clave, texto in OPCIONES_MENU:
            print(f"  [{clave}] {texto}")
        estado_aprendizaje = "ACTIVADO" if self.modo_aprendizaje else "DESACTIVADO"
        ui.mensaje_info(f"Modo aprendizaje: {estado_aprendizaje}")

    # ------------------------------------------------------------------
    # Escaneos
    # ------------------------------------------------------------------
    def _obtener_motor(self):
        if self.motor is None:
            self.motor = ScannerEngine()
        return self.motor

    def _flujo_escaneo(self, tipo):
        tema = self.config.get("tema")
        ui.titulo_seccion(f"ESCANEO: {tipo.upper()}", tema)
        objetivo = ui.entrada("IP o dominio a analizar: ", tema).strip()
        if not objetivo:
            ui.mensaje_error("Debes indicar un objetivo.")
            ui.pausar()
            return

        try:
            motor = self._obtener_motor()
        except ScannerEngineError as e:
            ui.mensaje_error(str(e))
            ui.pausar()
            return

        try:
            if tipo == "rapido":
                ui.barra_progreso("Ejecutando escaneo rápido...", tema=tema)
                resultado = motor.escaneo_rapido(objetivo, self.config.get("puertos_por_defecto"))
            elif tipo == "completo":
                ui.mensaje_info("El escaneo completo puede tardar varios minutos.")
                ui.barra_progreso("Ejecutando escaneo completo...", segundos=2.5, tema=tema)
                resultado = motor.escaneo_completo(objetivo)
            elif tipo == "personalizado":
                puertos = ui.entrada("Puertos (ej: 22,80,443 o 1-1000): ", tema).strip()
                ui.barra_progreso("Ejecutando escaneo personalizado...", tema=tema)
                resultado = motor.escaneo_personalizado(objetivo, puertos)
            elif tipo == "rango":
                inicio = ui.entrada("Puerto inicial: ", tema).strip()
                fin = ui.entrada("Puerto final: ", tema).strip()
                ui.barra_progreso("Escaneando rango de puertos...", tema=tema)
                resultado = motor.escaneo_rango_puertos(objetivo, inicio, fin)
            elif tipo == "so":
                ui.mensaje_info("La detección de SO puede requerir privilegios de administrador.")
                ui.barra_progreso("Detectando sistema operativo...", tema=tema)
                resultado = motor.deteccion_sistema_operativo(objetivo)
            elif tipo == "servicios":
                puertos = ui.entrada(
                    f"Puertos a analizar [{self.config.get('puertos_por_defecto')}]: ", tema
                ).strip() or self.config.get("puertos_por_defecto")
                ui.barra_progreso("Detectando servicios y versiones...", tema=tema)
                resultado = motor.deteccion_servicios(objetivo, puertos)
            else:
                resultado = None
        except ScannerEngineError as e:
            ui.mensaje_error(str(e))
            ui.pausar()
            return

        if not resultado:
            ui.mensaje_error("No se obtuvieron resultados. Verifica el objetivo e inténtalo de nuevo.")
            ui.pausar()
            return

        self._mostrar_resultado(resultado, tipo)

    def _mostrar_resultado(self, info_host, tipo):
        tema = self.config.get("tema")

        ui.titulo_seccion("INFORMACIÓN DEL HOST", tema)
        ui.imprimir_tabla(
            ["Campo", "Valor"],
            [
                ["IP", info_host["ip"]],
                ["Hostname", info_host["hostname"]],
                ["Sistema operativo", info_host["sistema_operativo"]],
                ["MAC", info_host["mac"]],
                ["Duración", f"{info_host['duracion_segundos']} s"],
            ],
            tema,
        )

        if info_host["puertos"]:
            ui.titulo_seccion("PUERTOS DETECTADOS", tema)
            filas = [[p["puerto"], p["estado"], p["servicio"], p["version"]] for p in info_host["puertos"]]
            ui.imprimir_tabla(["Puerto", "Estado", "Servicio", "Versión"], filas, tema)
        else:
            ui.mensaje_info("No se detectaron puertos abiertos.")

        analisis = security_analysis.calcular_nivel_seguridad(info_host)
        ui.titulo_seccion("ANÁLISIS DE SEGURIDAD", tema)
        print(f"  Nivel de seguridad: {analisis['puntaje']}/100")
        print(f"  Estado: {analisis['estado']}\n")
        print("  Recomendaciones:")
        for r in analisis["recomendaciones"]:
            print(f"    - {r}")

        if self.modo_aprendizaje:
            self._mostrar_modo_aprendizaje(info_host, tema)

        if self.config.get("auto_guardar_historial"):
            history.registrar_escaneo(info_host, analisis, tipo)

        self._ofrecer_reporte(info_host, analisis, tema)
        ui.pausar()

    def _mostrar_modo_aprendizaje(self, info_host, tema):
        explicaciones = learning_mode.generar_explicaciones_de_resultado(info_host)
        if not explicaciones:
            return
        ui.titulo_seccion("MODO APRENDIZAJE", tema)
        for puerto, ficha in explicaciones:
            print(f"\n  Puerto {puerto} — {ficha['nombre']}")
            print(f"    {ficha['descripcion']}")
            print(f"    ¿Por qué es importante? {ficha['importancia']}")
            print(f"    ¿Cómo se asegura correctamente? {ficha['aseguramiento']}")
            print(f"    ¿Cuáles son sus riesgos? {ficha['riesgos']}")

    def _ofrecer_reporte(self, info_host, analisis, tema):
        respuesta = ui.entrada("\n¿Deseas exportar un reporte? (txt/pdf/html/json/no): ", tema).strip().lower()
        if respuesta in ("no", "n", ""):
            return
        if respuesta not in reports.EXPORTADORES:
            ui.mensaje_error("Formato no reconocido.")
            return

        carpeta = os.path.join(BASE_DIR, self.config.get("ubicacion_reportes"))
        try:
            ruta = reports.exportar(respuesta, info_host, analisis, carpeta)
            ui.mensaje_ok(f"Reporte guardado en: {ruta}")
        except Exception as e:
            ui.mensaje_error(f"No se pudo generar el reporte: {e}")

    # ------------------------------------------------------------------
    # Historial
    # ------------------------------------------------------------------
    def _ver_historial(self):
        tema = self.config.get("tema")
        ui.titulo_seccion("HISTORIAL DE ESCANEOS", tema)
        registros = history.obtener_historial()
        if not registros:
            ui.mensaje_info("Aún no hay escaneos registrados.")
        else:
            filas = [
                [r["fecha"], r["tipo_escaneo"], r["ip"], r["puertos_abiertos"], f"{r['nivel_seguridad']}/100"]
                for r in registros
            ]
            ui.imprimir_tabla(["Fecha", "Tipo", "IP", "Puertos abiertos", "Seguridad"], filas, tema)
        ui.pausar()

    # ------------------------------------------------------------------
    # Configuración
    # ------------------------------------------------------------------
    def _menu_configuracion(self):
        tema = self.config.get("tema")
        while True:
            ui.titulo_seccion("CONFIGURACIÓN", tema)
            print(f"  [1] Tema de colores (actual: {self.config.get('tema')})")
            print(f"  [2] Puertos por defecto (actual: {self.config.get('puertos_por_defecto')})")
            print(f"  [3] Ubicación de reportes (actual: {self.config.get('ubicacion_reportes')})")
            print(f"  [4] Texto del banner (actual: {self.config.get('banner_texto')})")
            print(f"  [5] Guardado automático de historial (actual: {self.config.get('auto_guardar_historial')})")
            print("  [0] Volver")

            op = ui.entrada("\nSelecciona una opción: ", tema).strip()
            if op == "1":
                nuevo = ui.entrada("Tema (verde/azul/rojo/morado): ", tema).strip().lower()
                if nuevo in ("verde", "azul", "rojo", "morado"):
                    self.config.set("tema", nuevo)
                    ui.mensaje_ok("Tema actualizado.")
                else:
                    ui.mensaje_error("Tema no válido.")
            elif op == "2":
                nuevo = ui.entrada("Puertos por defecto (ej: 22,80,443): ", tema).strip()
                if nuevo:
                    self.config.set("puertos_por_defecto", nuevo)
                    ui.mensaje_ok("Puertos por defecto actualizados.")
            elif op == "3":
                nuevo = ui.entrada("Carpeta de reportes: ", tema).strip()
                if nuevo:
                    self.config.set("ubicacion_reportes", nuevo)
                    ui.mensaje_ok("Ubicación de reportes actualizada.")
            elif op == "4":
                nuevo = ui.entrada("Nuevo texto del banner: ", tema).strip()
                if nuevo:
                    self.config.set("banner_texto", nuevo)
                    ui.mensaje_ok("Banner actualizado.")
            elif op == "5":
                actual = self.config.get("auto_guardar_historial")
                self.config.set("auto_guardar_historial", not actual)
                ui.mensaje_ok(f"Guardado automático: {not actual}")
            elif op == "0":
                return
            else:
                ui.mensaje_error("Opción no válida.")
            ui.pausar()

    # ------------------------------------------------------------------
    def _toggle_modo_aprendizaje(self):
        self.modo_aprendizaje = not self.modo_aprendizaje
        estado = "activado" if self.modo_aprendizaje else "desactivado"
        ui.mensaje_ok(f"Modo aprendizaje {estado}.")
        ui.pausar()
