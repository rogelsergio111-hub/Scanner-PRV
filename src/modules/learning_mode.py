"""
learning_mode.py
Base de conocimiento educativa: explica puertos, protocolos, servicios
y conceptos generales de ciberseguridad detectados durante un análisis.
"""

EXPLICACIONES_PUERTOS = {
    21: {
        "nombre": "FTP",
        "descripcion": "Protocolo de transferencia de archivos. Permite subir y descargar archivos de un servidor.",
        "importancia": "Muy usado históricamente para compartir archivos entre equipos.",
        "aseguramiento": "Usar FTPS o SFTP en vez de FTP puro, y restringir el acceso por IP.",
        "riesgos": "Transmite usuario y contraseña sin cifrar, vulnerable a interceptación.",
    },
    22: {
        "nombre": "SSH",
        "descripcion": "Permite administrar equipos remotamente mediante conexiones cifradas.",
        "importancia": "Es el estándar para la administración remota segura de servidores.",
        "aseguramiento": "Usar autenticación por llaves, deshabilitar el login root y cambiar el puerto por defecto.",
        "riesgos": "Ataques de fuerza bruta si se permiten contraseñas débiles o acceso root directo.",
    },
    23: {
        "nombre": "Telnet",
        "descripcion": "Protocolo antiguo para acceso remoto a equipos, sin cifrado.",
        "importancia": "Fue el predecesor de SSH; hoy se considera obsoleto e inseguro.",
        "aseguramiento": "Reemplazarlo por SSH siempre que sea posible.",
        "riesgos": "Toda la información, incluidas credenciales, viaja en texto plano.",
    },
    25: {
        "nombre": "SMTP",
        "descripcion": "Protocolo usado para el envío de correo electrónico entre servidores.",
        "importancia": "Es la base del funcionamiento del correo electrónico en internet.",
        "aseguramiento": "Configurar SPF, DKIM y DMARC, y usar SMTP sobre TLS.",
        "riesgos": "Mal configurado puede usarse como relay abierto para enviar spam.",
    },
    53: {
        "nombre": "DNS",
        "descripcion": "Servicio que traduce nombres de dominio a direcciones IP.",
        "importancia": "Esencial para la navegación en internet y la resolución de nombres internos.",
        "aseguramiento": "Restringir transferencias de zona y aplicar DNSSEC cuando sea posible.",
        "riesgos": "Puede ser usado para ataques de amplificación DDoS o envenenamiento de caché.",
    },
    80: {
        "nombre": "HTTP",
        "descripcion": "Protocolo de transferencia de hipertexto usado por la web sin cifrado.",
        "importancia": "Base histórica de la navegación web.",
        "aseguramiento": "Redirigir siempre a HTTPS y usar cabeceras de seguridad adecuadas.",
        "riesgos": "El tráfico viaja sin cifrar, exponiendo datos sensibles.",
    },
    110: {
        "nombre": "POP3",
        "descripcion": "Protocolo para descargar correos electrónicos desde un servidor.",
        "importancia": "Permite a los clientes de correo obtener mensajes del servidor.",
        "aseguramiento": "Usar POP3S (con TLS) en vez de la versión sin cifrar.",
        "riesgos": "Sin cifrado, expone credenciales y contenido del correo.",
    },
    143: {
        "nombre": "IMAP",
        "descripcion": "Protocolo para gestionar correo electrónico directamente en el servidor.",
        "importancia": "Permite sincronizar el correo entre varios dispositivos.",
        "aseguramiento": "Usar IMAPS (con TLS) en lugar de la versión sin cifrar.",
        "riesgos": "Sin cifrado, expone credenciales y mensajes.",
    },
    443: {
        "nombre": "HTTPS",
        "descripcion": "Versión cifrada de HTTP mediante TLS/SSL.",
        "importancia": "Estándar actual para toda comunicación web segura.",
        "aseguramiento": "Mantener certificados actualizados y usar versiones modernas de TLS.",
        "riesgos": "Certificados mal configurados o TLS desactualizado reducen la protección real.",
    },
    445: {
        "nombre": "SMB",
        "descripcion": "Protocolo para compartir archivos e impresoras en redes Windows.",
        "importancia": "Muy usado en redes corporativas para compartir recursos.",
        "aseguramiento": "Deshabilitar SMBv1 y restringir el acceso solo a la red interna.",
        "riesgos": "Ha sido explotado por malware como WannaCry a través de vulnerabilidades conocidas.",
    },
    3306: {
        "nombre": "MySQL",
        "descripcion": "Puerto por defecto del motor de base de datos MySQL/MariaDB.",
        "importancia": "Permite conexiones remotas a la base de datos.",
        "aseguramiento": "No exponerlo a internet; usar túneles SSH o VPN para administración remota.",
        "riesgos": "Expuesto a internet, es blanco de ataques de fuerza bruta y explotación de vulnerabilidades.",
    },
    3389: {
        "nombre": "RDP",
        "descripcion": "Protocolo de escritorio remoto de Windows.",
        "importancia": "Permite controlar un equipo Windows de forma remota con interfaz gráfica.",
        "aseguramiento": "Usar VPN, autenticación multifactor y limitar el acceso por IP.",
        "riesgos": "Uno de los vectores de ataque más comunes para ransomware si está expuesto a internet.",
    },
    8080: {
        "nombre": "HTTP alternativo",
        "descripcion": "Puerto alternativo comúnmente usado para proxies o servidores de aplicaciones web.",
        "importancia": "Se usa para pruebas o servicios web secundarios.",
        "aseguramiento": "Aplicar las mismas protecciones que a un servidor HTTP estándar.",
        "riesgos": "A menudo se usa para servicios de desarrollo que quedan expuestos por error.",
    },
}

EXPLICACIONES_CONCEPTOS = {
    "firewall": "Un firewall es un sistema que filtra el tráfico de red permitiendo o bloqueando "
                "conexiones según reglas definidas, actuando como primera línea de defensa perimetral.",
    "sistema_operativo": "El sistema operativo detectado ayuda a estimar qué vulnerabilidades conocidas "
                          "podrían aplicar al equipo, según sus parches y versión.",
    "protocolo": "Un protocolo es un conjunto de reglas que define cómo se comunican dos sistemas; "
                 "algunos cifran la información (seguros) y otros la transmiten en texto plano (inseguros).",
    "vulnerabilidad": "Una vulnerabilidad es una debilidad en un sistema que puede ser aprovechada "
                       "para comprometer su confidencialidad, integridad o disponibilidad.",
    "escaneo_puertos": "Escanear puertos consiste en probar qué servicios responden en un equipo, "
                        "lo cual es el primer paso tanto de una auditoría legítima como de un ataque.",
}


def explicar_puerto(puerto):
    return EXPLICACIONES_PUERTOS.get(puerto)


def explicar_concepto(clave):
    return EXPLICACIONES_CONCEPTOS.get(clave)


def generar_explicaciones_de_resultado(info_host):
    """
    Devuelve una lista de explicaciones educativas relevantes
    para los puertos abiertos encontrados en un escaneo.
    """
    explicaciones = []
    for p in info_host["puertos"]:
        if p["estado"] != "open":
            continue
        ficha = explicar_puerto(p["puerto"])
        if ficha:
            explicaciones.append((p["puerto"], ficha))
    return explicaciones
