"""
validators.py
Valida las entradas del usuario (objetivo, puertos, rangos) antes de que
lleguen al motor de escaneo, para evitar inyección de argumentos hacia Nmap.

python-nmap ejecuta internamente shlex.split() sobre el string de "hosts",
por lo que un valor con espacios o flags (--script=, -oN, etc.) puede
inyectar argumentos arbitrarios a la línea de comandos real de Nmap.
Esta capa rechaza cualquier entrada que no luzca estrictamente como un
host, IP, rango o lista de puertos.
"""

import re

# Solo letras, números, punto, guion, dos puntos y barra (para IPv6/CIDR).
# Nada de espacios, comillas, símbolos de shell ni guiones al inicio.
_PATRON_OBJETIVO = re.compile(r"^[a-zA-Z0-9.\-:/]+$")

# Puertos: números, comas y guiones únicamente (ej: "22,80,443" o "1-1000")
_PATRON_PUERTOS = re.compile(r"^[0-9,\-]+$")


class ValidationError(Exception):
    pass


def _rechazar_si_empieza_con_guion(valor, nombre_campo):
    if valor.startswith("-"):
        raise ValidationError(
            f"El valor de '{nombre_campo}' no puede empezar con '-' "
            f"(podría interpretarse como una opción de Nmap)."
        )


def validar_objetivo(objetivo):
    """
    Valida IPs, hostnames, rangos CIDR o rangos de IP tipo Nmap
    (ej: 192.168.1.1, example.com, 192.168.1.0/24, 192.168.1.1-50).
    Lanza ValidationError si el valor es sospechoso o inválido.
    """
    objetivo = (objetivo or "").strip()

    if not objetivo:
        raise ValidationError("Debes indicar un objetivo (IP, dominio o rango).")

    if " " in objetivo or "\t" in objetivo:
        raise ValidationError(
            "El objetivo no puede contener espacios (posible intento de "
            "inyectar argumentos adicionales a Nmap)."
        )

    _rechazar_si_empieza_con_guion(objetivo, "objetivo")

    if not _PATRON_OBJETIVO.match(objetivo):
        raise ValidationError(
            "El objetivo contiene caracteres no permitidos. Solo se aceptan "
            "letras, números, puntos, guiones, ':' y '/' (para IPv6/CIDR)."
        )

    return objetivo


def validar_puertos(puertos):
    """
    Valida una especificación de puertos tipo Nmap (ej: "22,80,443" o "1-1000").
    """
    puertos = (puertos or "").strip()

    if not puertos:
        raise ValidationError("Debes indicar al menos un puerto o rango.")

    if " " in puertos or "\t" in puertos:
        raise ValidationError("La especificación de puertos no puede contener espacios.")

    _rechazar_si_empieza_con_guion(puertos, "puertos")

    if not _PATRON_PUERTOS.match(puertos):
        raise ValidationError(
            "La especificación de puertos solo puede contener números, comas y guiones."
        )

    return puertos


def validar_puerto_individual(valor, nombre_campo="puerto"):
    """
    Valida un único número de puerto (usado en 'inicio' y 'fin' del rango).
    """
    valor = (valor or "").strip()

    _rechazar_si_empieza_con_guion(valor, nombre_campo)

    if not valor.isdigit():
        raise ValidationError(f"'{nombre_campo}' debe ser un número entero positivo.")

    numero = int(valor)
    if not (0 <= numero <= 65535):
        raise ValidationError(f"'{nombre_campo}' debe estar entre 0 y 65535.")

    return valor
