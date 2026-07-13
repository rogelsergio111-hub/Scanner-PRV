# Scanner PRV

> Scanner PRV no es solo un escáner de red. Es una herramienta diseñada para que cada análisis también sea una oportunidad para aprender ciberseguridad.

Scanner PRV es una herramienta profesional de auditoría de redes desarrollada en Python. Utiliza el motor de **Nmap** para el análisis técnico, pero ofrece una interfaz mucho más organizada, intuitiva y educativa — pensada especialmente para estudiantes de redes y ciberseguridad.

Scanner PRV no pretende reemplazar a Nmap: aprovecha toda su potencia y la presenta de forma clara y moderna.

## Filosofía

- **Automatizar** auditorías básicas de red.
- **Enseñar** conceptos de redes y ciberseguridad durante cada análisis.
- **Documentar** cada auditoría con reportes profesionales.

## Características

- Menú principal con banner profesional (Colorama + Pyfiglet).
- Escaneo rápido, completo, personalizado y por rango de puertos.
- Detección de sistema operativo y de servicios/versiones.
- Análisis de seguridad con puntaje (0-100) y recomendaciones automáticas.
- **Modo aprendizaje**: cada puerto detectado incluye una explicación educativa (qué es, por qué importa, cómo se asegura, qué riesgos tiene).
- Exportación de reportes en TXT, JSON, HTML y PDF.
- Historial de auditorías anteriores.
- Configuración personalizable (tema de colores, puertos por defecto, ubicación de reportes, banner).

## Requisitos previos

- Python 3.9 o superior.
- [Nmap](https://nmap.org/download.html) instalado en el sistema y accesible desde la terminal (`nmap -v`).
- Algunas funciones (detección de sistema operativo, ciertos escaneos SYN) requieren ejecutar con permisos de administrador/root.

## Instalación

### Opción A — Instalación automática (Linux/Mac, recomendado)

```bash
git clone https://github.com/tu-usuario/Scanner-PRV.git
cd Scanner-PRV
chmod +x install.sh
./install.sh
```

El script instala `nmap` si falta, crea un entorno virtual (`venv`) e instala las dependencias de Python dentro de él. Así evitas el error `externally-managed-environment` que da Python en distribuciones recientes de Debian/Ubuntu al intentar instalar paquetes con `pip` directamente en el sistema.

### Opción B — Instalación manual

**Linux/Mac:**
```bash
git clone https://github.com/tu-usuario/Scanner-PRV.git
cd Scanner-PRV
sudo apt install nmap python3-venv python3-full -y   # Debian/Ubuntu
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/tu-usuario/Scanner-PRV.git
cd Scanner-PRV
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```
Instala Nmap para Windows desde https://nmap.org/download.html (marca la opción de agregarlo al PATH durante la instalación).

> Si al hacer `pip install` ves el error `externally-managed-environment`, significa que intentaste instalar fuera de un entorno virtual. Usa siempre `venv` como se indica arriba (o, como último recurso, `pip install -r requirements.txt --break-system-packages`, no recomendado).

## Uso

Con el entorno virtual activado (`source venv/bin/activate` en Linux/Mac, o `venv\Scripts\activate` en Windows):

```bash
python scanner.py
```

O sin activar el entorno, invocando el Python del venv directamente:

```bash
venv/bin/python scanner.py          # Linux/Mac
venv\Scripts\python.exe scanner.py  # Windows
```

**Para la detección de sistema operativo** (opción 5 del menú), Nmap necesita privilegios de administrador:

```bash
sudo venv/bin/python scanner.py     # Linux/Mac
```
En Windows, abre la terminal "como Administrador" antes de ejecutar el comando.

Sigue el menú interactivo para elegir el tipo de escaneo, revisar el análisis de seguridad, activar el modo aprendizaje y exportar reportes.

## Estructura del proyecto

```
Scanner-PRV/
├── scanner.py              # Punto de entrada
├── requirements.txt
├── README.md
├── LICENSE
├── reportes/                # Reportes exportados (TXT/JSON/HTML/PDF)
├── historial/                # Historial de escaneos (JSON)
├── logs/
├── docs/
├── imagenes/
├── config/
│   └── config.json          # Configuración persistente
└── src/
    └── modules/
        ├── app.py                # Controlador principal / menús
        ├── scanner_engine.py     # Capa sobre python-nmap
        ├── security_analysis.py  # Puntaje y recomendaciones
        ├── learning_mode.py      # Base de conocimiento educativa
        ├── reports.py            # Exportación de reportes
        ├── history.py            # Historial de escaneos
        ├── config_manager.py     # Configuración
        └── ui.py                 # Banner, colores, tablas, progreso
```

## Tecnologías

Python · Nmap · python-nmap · Colorama · Pyfiglet · fpdf2

## Solución de problemas comunes

**`error: externally-managed-environment` al instalar dependencias**
Estás intentando instalar con `pip` fuera de un entorno virtual. Usa `./install.sh` o crea el `venv` manualmente (ver sección de Instalación).

**La detección de sistema operativo falla con "requires root privileges"**
Ejecuta el programa con `sudo` (Linux/Mac) o como Administrador (Windows), usando el Python del entorno virtual: `sudo venv/bin/python scanner.py`.

**La detección de sistema operativo no encuentra nada aunque uses `sudo`**
Nmap necesita ver al menos un puerto abierto (idealmente uno abierto y uno cerrado) para analizar cómo responde la pila TCP/IP del objetivo. Si el escaneo no detectó puertos abiertos, prueba contra un equipo que sí tenga servicios activos (por ejemplo tu router, normalmente en `192.168.1.1`), o revisa que el firewall del objetivo no esté bloqueando las sondas.

## Aviso legal

Usa Scanner PRV únicamente en redes y equipos sobre los que tengas autorización explícita para realizar auditorías. El escaneo de redes de terceros sin permiso puede ser ilegal según la legislación de tu país.

## Roadmap

- Interfaz gráfica (GUI/web) en versiones futuras.
- Nuevas reglas de análisis de seguridad.
- Ampliación del glosario del modo aprendizaje.

## Licencia

Ver [LICENSE](LICENSE).
