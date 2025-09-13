#!/bin/bash

echo "Building StrongDM Resource Manager for macOS (Simple Version)..."

# Check if we're on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "Warning: This script is designed for macOS. Current OS: $OSTYPE"
fi

# Install required packages
echo "Installing dependencies..."
pip3 install pyinstaller strongdm

# Build standalone executable (simpler, more reliable)
echo "Building standalone executable..."
pyinstaller --onefile --windowed --name "StrongDM-Manager" strongdm_manager.py

# Copy additional files to dist folder
echo "Copying additional files..."
cp requirements.txt dist/ 2>/dev/null || true
cp sample_*.csv dist/ 2>/dev/null || true
cp README.md dist/ 2>/dev/null || true
cp CLAUDE.md dist/ 2>/dev/null || true

echo ""
echo "Build complete!"
echo ""
echo "Available files:"
echo "✓ macOS executable: dist/StrongDM-Manager"
echo "✓ Sample CSV files: dist/sample_*.csv"
echo "✓ Documentation: dist/README.md"
echo ""
echo "To run: ./dist/StrongDM-Manager"
echo "To install globally: sudo cp dist/StrongDM-Manager /usr/local/bin/"