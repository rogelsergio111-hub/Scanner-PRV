"""
security_analysis.py
Calcula un nivel de seguridad estimado a partir de los resultados
de un escaneo y genera recomendaciones automáticas.
"""

PUERTOS_RIESGO_ALTO = {21, 23, 445, 3389, 135, 139}
PUERTOS_RIESGO_MEDIO = {22, 3306, 5432, 1433, 6379, 27017}
SERVICIOS_INSEGUROS = {"telnet", "ftp", "rsh", "rlogin", "tftp"}


def calcular_nivel_seguridad(info_host):
    puntaje = 100
    hallazgos = []

    puertos_abiertos = [p for p in info_host["puertos"] if p["estado"] == "open"]

    for p in puertos_abiertos:
        puerto = p["puerto"]
        servicio = p["servicio"].lower()

        if puerto in PUERTOS_RIESGO_ALTO or servicio in SERVICIOS_INSEGUROS:
            puntaje -= 12
            hallazgos.append(f"Puerto {puerto} ({servicio}) representa un riesgo alto y usa protocolos sin cifrar o expuestos.")
        elif puerto in PUERTOS_RIESGO_MEDIO:
            puntaje -= 6
            hallazgos.append(f"Puerto {puerto} ({servicio}) representa un riesgo medio si no está bien asegurado.")
        else:
            puntaje -= 2

    if len(puertos_abiertos) > 10:
        puntaje -= 10
        hallazgos.append("Gran cantidad de puertos abiertos: superficie de ataque amplia.")

    puntaje = max(0, min(100, puntaje))

    if puntaje >= 90:
        estado = "Excelente"
    elif puntaje >= 75:
        estado = "Bueno"
    elif puntaje >= 50:
        estado = "Regular"
    else:
        estado = "Crítico"

    recomendaciones = _generar_recomendaciones(puertos_abiertos, hallazgos)

    return {
        "puntaje": puntaje,
        "estado": estado,
        "hallazgos": hallazgos,
        "recomendaciones": recomendaciones,
    }


def _generar_recomendaciones(puertos_abiertos, hallazgos):
    recomendaciones = []

    if any(p["puerto"] in PUERTOS_RIESGO_ALTO for p in puertos_abiertos):
        recomendaciones.append("Cerrar o restringir puertos innecesarios de alto riesgo (21, 23, 445, 3389, entre otros).")

    if any(p["servicio"].lower() in SERVICIOS_INSEGUROS for p in puertos_abiertos):
        recomendaciones.append("Desactivar protocolos inseguros como Telnet o FTP; usar SSH/SFTP en su lugar.")

    if len(puertos_abiertos) > 10:
        recomendaciones.append("Revisar y reducir la cantidad de servicios expuestos al exterior.")

    recomendaciones.append("Mantener actualizados los servicios detectados a sus últimas versiones estables.")
    recomendaciones.append("Configurar un firewall que filtre el tráfico entrante no necesario.")

    if not hallazgos:
        recomendaciones.append("No se detectaron riesgos evidentes; mantener buenas prácticas de monitoreo.")

    return recomendaciones
