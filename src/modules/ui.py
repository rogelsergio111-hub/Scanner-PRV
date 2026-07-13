"""
ui.py
Elementos visuales: banner, colores, tablas y utilidades de consola.
"""

import time
import shutil
from colorama import Fore, Style, init
import pyfiglet

init(autoreset=True)

TEMAS = {
    "verde": Fore.GREEN,
    "azul": Fore.CYAN,
    "rojo": Fore.RED,
    "morado": Fore.MAGENTA,
}


def color_tema(tema):
    return TEMAS.get(tema, Fore.GREEN)


def mostrar_banner(texto="Scanner PRV", tema="verde"):
    color = color_tema(tema)
    limpiar_pantalla_soft()
    arte = pyfiglet.figlet_format(texto, font="slant")
    print(color + arte)
    print(color + Style.BRIGHT + "  Auditoría de redes profesional y educativa · basada en Nmap")
    print(color + "  " + "-" * 60 + Style.RESET_ALL)


def limpiar_pantalla_soft():
    print("\n" * 2)


def titulo_seccion(texto, tema="verde"):
    color = color_tema(tema)
    ancho = shutil.get_terminal_size((70, 20)).columns
    print("\n" + color + "═" * min(ancho, 70))
    print(color + Style.BRIGHT + f" {texto}")
    print(color + "═" * min(ancho, 70) + Style.RESET_ALL)


def imprimir_tabla(encabezados, filas, tema="verde"):
    color = color_tema(tema)
    anchos = [len(str(h)) for h in encabezados]
    for fila in filas:
        for i, celda in enumerate(fila):
            anchos[i] = max(anchos[i], len(str(celda)))

    def linea_separadora(izq, medio, der, relleno="─"):
        return izq + medio.join(relleno * (a + 2) for a in anchos) + der

    print(color + linea_separadora("┌", "┬", "┐"))
    fila_txt = "│ " + " │ ".join(str(h).ljust(anchos[i]) for i, h in enumerate(encabezados)) + " │"
    print(color + Style.BRIGHT + fila_txt + Style.RESET_ALL)
    print(color + linea_separadora("├", "┼", "┤"))
    for fila in filas:
        fila_txt = "│ " + " │ ".join(str(c).ljust(anchos[i]) for i, c in enumerate(fila)) + " │"
        print(Style.RESET_ALL + fila_txt)
    print(color + linea_separadora("└", "┴", "┘") + Style.RESET_ALL)


def barra_progreso(mensaje, segundos=1.2, tema="verde"):
    color = color_tema(tema)
    ancho = 30
    print(color + mensaje)
    for i in range(ancho + 1):
        pct = int((i / ancho) * 100)
        barra = "█" * i + "░" * (ancho - i)
        print(color + f"\r  [{barra}] {pct}%", end="", flush=True)
        time.sleep(segundos / ancho)
    print()


def pausar():
    input(Fore.WHITE + "\nPresiona ENTER para continuar..." + Style.RESET_ALL)


def entrada(texto, tema="verde"):
    color = color_tema(tema)
    return input(color + texto + Style.RESET_ALL)


def mensaje_ok(texto):
    print(Fore.GREEN + "✔ " + texto + Style.RESET_ALL)


def mensaje_error(texto):
    print(Fore.RED + "✘ " + texto + Style.RESET_ALL)


def mensaje_info(texto):
    print(Fore.YELLOW + "ℹ " + texto + Style.RESET_ALL)
