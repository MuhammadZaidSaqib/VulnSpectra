#!/bin/bash
# VulnSpectra Quick Start Script for Linux/Mac

echo "========================================"
echo "VulnSpectra - Quick Start"
echo "========================================"
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed"
    echo "Please install Python 3.8+ from your package manager"
    exit 1
fi

echo "[OK] Python found"
echo ""

# Check if dependencies are installed
echo "Checking dependencies..."
if ! python3 -c "import fastapi" 2>/dev/null; then
    echo "[INFO] Installing dependencies..."
    pip3 install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to install dependencies"
        exit 1
    fi
else
    echo "[OK] Dependencies installed"
fi

echo ""
echo "========================================"
echo "Starting VulnSpectra Dashboard"
echo "========================================"
echo ""
echo "Dashboard will open in your browser"
echo "API Server: http://localhost:8000"
echo ""
echo "Press Ctrl+C to stop"
echo ""

sudo python3 main.py --dashboard

