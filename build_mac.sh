#!/bin/bash

echo "Building StrongDM Resource Manager for macOS..."

# Check if we're on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "Warning: This script is designed for macOS. Current OS: $OSTYPE"
    echo "Continuing anyway, but the app bundle may not work properly..."
fi

# Install required packages
echo "Installing dependencies..."
pip3 install pyinstaller strongdm

# Build macOS app bundle
echo "Building application bundle..."
pyinstaller --onefile --windowed --name "StrongDM-Manager" \
    --osx-bundle-identifier "com.strongdm.manager" \
    --icon=app_icon.icns \
    strongdm_manager.py

# Create a more user-friendly .app bundle structure
echo "Creating macOS app bundle..."
pyinstaller --windowed --name "StrongDM-Manager" \
    --osx-bundle-identifier "com.strongdm.manager" \
    --add-data "requirements.txt:." \
    --add-data "*.csv:." \
    --add-data "README.md:." \
    strongdm_manager.py

# Copy additional files to dist folder
echo "Copying additional files..."
cp requirements.txt dist/ 2>/dev/null || true
cp sample_*.csv dist/ 2>/dev/null || true
cp README.md dist/ 2>/dev/null || true
cp CLAUDE.md dist/ 2>/dev/null || true

# Create a simple installation package structure
echo "Creating installation package structure..."
mkdir -p dist/StrongDM-Manager-Package
cp -r dist/StrongDM-Manager.app dist/StrongDM-Manager-Package/ 2>/dev/null || true
cp dist/StrongDM-Manager dist/StrongDM-Manager-Package/ 2>/dev/null || true
cp requirements.txt dist/StrongDM-Manager-Package/ 2>/dev/null || true
cp sample_*.csv dist/StrongDM-Manager-Package/ 2>/dev/null || true
cp README.md dist/StrongDM-Manager-Package/ 2>/dev/null || true

# Create a simple installer script
cat > dist/StrongDM-Manager-Package/install.sh << 'EOF'
#!/bin/bash
echo "Installing StrongDM Manager..."

# Copy app to Applications folder (requires admin)
if [ -d "StrongDM-Manager.app" ]; then
    echo "Installing app bundle to /Applications..."
    sudo cp -R StrongDM-Manager.app /Applications/
    echo "App bundle installed! You can find it in Applications."
fi

# Make standalone executable accessible
if [ -f "StrongDM-Manager" ]; then
    echo "Installing command-line executable..."
    sudo cp StrongDM-Manager /usr/local/bin/
    echo "Command-line executable installed! Run with: StrongDM-Manager"
fi

echo "Installation complete!"
echo ""
echo "You can now:"
echo "1. Run the GUI app from Applications/StrongDM-Manager.app"
echo "2. Run from terminal with: StrongDM-Manager"
echo "3. Use the sample CSV files for bulk imports"
EOF

chmod +x dist/StrongDM-Manager-Package/install.sh

# Create DMG if hdiutil is available (macOS only)
if command -v hdiutil &> /dev/null && [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Creating DMG installer..."
    hdiutil create -volname "StrongDM Manager" -srcfolder dist/StrongDM-Manager-Package -ov -format UDZO dist/StrongDM-Manager.dmg
    echo "DMG created: dist/StrongDM-Manager.dmg"
fi

echo ""
echo "Build complete!"
echo ""
echo "Available files:"
if [ -f "dist/StrongDM-Manager.app/Contents/MacOS/StrongDM-Manager" ]; then
    echo "✓ macOS App Bundle: dist/StrongDM-Manager.app"
fi
if [ -f "dist/StrongDM-Manager" ]; then
    echo "✓ Standalone executable: dist/StrongDM-Manager"
fi
if [ -f "dist/StrongDM-Manager.dmg" ]; then
    echo "✓ DMG installer: dist/StrongDM-Manager.dmg"
fi
echo "✓ Installation package: dist/StrongDM-Manager-Package/"
echo ""
echo "To install on macOS:"
echo "1. Use the DMG installer (recommended): open dist/StrongDM-Manager.dmg"
echo "2. Or run the install script: cd dist/StrongDM-Manager-Package && ./install.sh"
echo ""
echo "To run without installing:"
echo "1. GUI: open dist/StrongDM-Manager.app"
echo "2. Terminal: ./dist/StrongDM-Manager"