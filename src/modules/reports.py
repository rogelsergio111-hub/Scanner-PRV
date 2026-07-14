"""
reports.py
Genera reportes de auditoría en distintos formatos: TXT, JSON, HTML y PDF.
"""

import html
import json
import os
from datetime import datetime


def _nombre_base(info_host):
    ip = info_host["ip"].replace(".", "-").replace(":", "-")
    marca = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"reporte_{ip}_{marca}"


def _construir_payload(info_host, analisis_seguridad):
    return {
        "fecha": datetime.now().strftime("%Y-%m-%d"),
        "hora": datetime.now().strftime("%H:%M:%S"),
        "equipo_analizado": info_host["ip"],
        "hostname": info_host["hostname"],
        "sistema_operativo": info_host["sistema_operativo"],
        "mac": info_host["mac"],
        "duracion_segundos": info_host["duracion_segundos"],
        "puertos": info_host["puertos"],
        "nivel_seguridad": analisis_seguridad["puntaje"],
        "estado_seguridad": analisis_seguridad["estado"],
        "hallazgos": analisis_seguridad["hallazgos"],
        "recomendaciones": analisis_seguridad["recomendaciones"],
    }


def exportar_json(info_host, analisis_seguridad, carpeta):
    os.makedirs(carpeta, exist_ok=True)
    payload = _construir_payload(info_host, analisis_seguridad)
    ruta = os.path.join(carpeta, _nombre_base(info_host) + ".json")
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4, ensure_ascii=False)
    return ruta


def exportar_txt(info_host, analisis_seguridad, carpeta):
    os.makedirs(carpeta, exist_ok=True)
    payload = _construir_payload(info_host, analisis_seguridad)
    ruta = os.path.join(carpeta, _nombre_base(info_host) + ".txt")

    lineas = [
        "SCANNER PRV - REPORTE DE AUDITORÍA",
        "=" * 50,
        f"Fecha: {payload['fecha']}    Hora: {payload['hora']}",
        f"Equipo analizado: {payload['equipo_analizado']} ({payload['hostname']})",
        f"Sistema operativo: {payload['sistema_operativo']}",
        f"MAC: {payload['mac']}",
        f"Duración del análisis: {payload['duracion_segundos']} s",
        "",
        "PUERTOS Y SERVICIOS",
        "-" * 50,
    ]
    for p in payload["puertos"]:
        lineas.append(f"  {p['puerto']}/{p['protocolo']}  {p['estado']:10s}  {p['servicio']:12s}  {p['version']}")

    lineas += [
        "",
        "NIVEL DE SEGURIDAD",
        "-" * 50,
        f"  Puntaje: {payload['nivel_seguridad']}/100  ({payload['estado_seguridad']})",
        "",
        "HALLAZGOS",
        "-" * 50,
    ]
    lineas += [f"  - {h}" for h in payload["hallazgos"]] or ["  (sin hallazgos relevantes)"]

    lineas += ["", "RECOMENDACIONES", "-" * 50]
    lineas += [f"  - {r}" for r in payload["recomendaciones"]]

    with open(ruta, "w", encoding="utf-8") as f:
        f.write("\n".join(lineas))
    return ruta


def exportar_html(info_host, analisis_seguridad, carpeta):
    os.makedirs(carpeta, exist_ok=True)
    payload = _construir_payload(info_host, analisis_seguridad)
    ruta = os.path.join(carpeta, _nombre_base(info_host) + ".html")

    # Los datos de puertos/servicio/version/hostname/SO provienen del equipo
    # escaneado (banners remotos), no de Scanner PRV, así que se escapan
    # antes de insertarlos en el HTML para evitar XSS almacenado.
    def e(valor):
        return html.escape(str(valor), quote=True)

    filas_puertos = "".join(
        f"<tr><td>{e(p['puerto'])}</td><td>{e(p['protocolo'])}</td><td>{e(p['estado'])}</td>"
        f"<td>{e(p['servicio'])}</td><td>{e(p['version'])}</td></tr>"
        for p in payload["puertos"]
    )
    hallazgos_html = "".join(f"<li>{e(h)}</li>" for h in payload["hallazgos"]) or "<li>Sin hallazgos relevantes</li>"
    recomendaciones_html = "".join(f"<li>{e(r)}</li>" for r in payload["recomendaciones"])

    contenido_html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Reporte Scanner PRV - {e(payload['equipo_analizado'])}</title>
<style>
  body {{ font-family: Arial, sans-serif; background:#0f172a; color:#e2e8f0; padding:30px; }}
  h1 {{ color:#22c55e; }}
  h2 {{ color:#4ade80; border-bottom:1px solid #334155; padding-bottom:5px; }}
  table {{ border-collapse: collapse; width:100%; margin-bottom:20px; }}
  th, td {{ border:1px solid #334155; padding:8px; text-align:left; }}
  th {{ background:#1e293b; }}
  .puntaje {{ font-size:1.5em; font-weight:bold; color:#22c55e; }}
</style>
</head>
<body>
  <h1>Scanner PRV — Reporte de auditoría</h1>
  <p>Fecha: {e(payload['fecha'])} — Hora: {e(payload['hora'])}</p>
  <h2>Información del equipo</h2>
  <p>IP: {e(payload['equipo_analizado'])} ({e(payload['hostname'])})<br>
     Sistema operativo: {e(payload['sistema_operativo'])}<br>
     MAC: {e(payload['mac'])}<br>
     Duración del análisis: {e(payload['duracion_segundos'])} s</p>

  <h2>Puertos y servicios</h2>
  <table>
    <tr><th>Puerto</th><th>Protocolo</th><th>Estado</th><th>Servicio</th><th>Versión</th></tr>
    {filas_puertos}
  </table>

  <h2>Nivel de seguridad</h2>
  <p class="puntaje">{e(payload['nivel_seguridad'])}/100 — {e(payload['estado_seguridad'])}</p>

  <h2>Hallazgos</h2>
  <ul>{hallazgos_html}</ul>

  <h2>Recomendaciones</h2>
  <ul>{recomendaciones_html}</ul>
</body>
</html>"""

    with open(ruta, "w", encoding="utf-8") as f:
        f.write(contenido_html)
    return ruta


def exportar_pdf(info_host, analisis_seguridad, carpeta):
    from fpdf import FPDF

    os.makedirs(carpeta, exist_ok=True)
    payload = _construir_payload(info_host, analisis_seguridad)
    ruta = os.path.join(carpeta, _nombre_base(info_host) + ".pdf")

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Scanner PRV - Reporte de auditoria", ln=True)

    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, f"Fecha: {payload['fecha']}  Hora: {payload['hora']}", ln=True)
    pdf.cell(0, 8, f"Equipo: {payload['equipo_analizado']} ({payload['hostname']})", ln=True)
    pdf.cell(0, 8, f"Sistema operativo: {payload['sistema_operativo']}", ln=True)
    pdf.cell(0, 8, f"MAC: {payload['mac']}", ln=True)
    pdf.cell(0, 8, f"Duracion: {payload['duracion_segundos']} s", ln=True)

    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Puertos y servicios", ln=True)
    pdf.set_font("Helvetica", "", 10)
    for p in payload["puertos"]:
        linea = f"{p['puerto']}/{p['protocolo']}  {p['estado']}  {p['servicio']}  {p['version']}"
        pdf.multi_cell(0, 6, linea)

    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, f"Nivel de seguridad: {payload['nivel_seguridad']}/100 ({payload['estado_seguridad']})", ln=True)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Hallazgos", ln=True)
    pdf.set_font("Helvetica", "", 10)
    for h in payload["hallazgos"] or ["Sin hallazgos relevantes"]:
        pdf.multi_cell(0, 6, f"- {h}")

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Recomendaciones", ln=True)
    pdf.set_font("Helvetica", "", 10)
    for r in payload["recomendaciones"]:
        pdf.multi_cell(0, 6, f"- {r}")

    pdf.output(ruta)
    return ruta


EXPORTADORES = {
    "txt": exportar_txt,
    "json": exportar_json,
    "html": exportar_html,
    "pdf": exportar_pdf,
}


def exportar(formato, info_host, analisis_seguridad, carpeta):
    funcion = EXPORTADORES.get(formato.lower())
    if not funcion:
        raise ValueError(f"Formato no soportado: {formato}")
    return funcion(info_host, analisis_seguridad, carpeta)
