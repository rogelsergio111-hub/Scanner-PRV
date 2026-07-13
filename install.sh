#!/usr/bin/env bash
# install.sh — instalación automática de Scanner PRV (Linux/Mac)
set -e

echo "== Scanner PRV: instalación =="

# 1. Verifica/instala nmap
if ! command -v nmap >/dev/null 2>&1; then
    echo "-> nmap no encontrado."
    if command -v apt >/dev/null 2>&1; then
        echo "-> Instalando nmap con apt (puede pedir tu contraseña)..."
        sudo apt update && sudo apt install -y nmap python3-venv python3-full
    elif command -v brew >/dev/null 2>&1; then
        echo "-> Instalando nmap con Homebrew..."
        brew install nmap
    else
        echo "!! No se pudo instalar nmap automáticamente."
        echo "   Instálalo manualmente: https://nmap.org/download.html"
        exit 1
    fi
else
    echo "-> nmap ya está instalado: $(nmap --version | head -n1)"
fi

# 2. Crea el entorno virtual si no existe
if [ ! -d "venv" ]; then
    echo "-> Creando entorno virtual (venv)..."
    python3 -m venv venv
fi

# 3. Instala las dependencias dentro del venv
echo "-> Instalando dependencias de Python..."
venv/bin/pip install --upgrade pip
venv/bin/pip install -r requirements.txt

echo ""
echo "== Instalación completa =="
echo "Para usar Scanner PRV:"
echo "  Escaneos normales:            venv/bin/python scanner.py"
echo "  Con detección de SO (root):   sudo venv/bin/python scanner.py"
