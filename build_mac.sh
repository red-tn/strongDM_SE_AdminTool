#!/bin/bash

echo "Building StrongDM Resource Manager for macOS (Fixed)..."

# Check if we're on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "Warning: This script is designed for macOS. Current OS: $OSTYPE"
fi

# Create and activate virtual environment
echo "Creating virtual environment..."
python3 -m venv build_env
source build_env/bin/activate

# Install required packages in virtual environment
echo "Installing dependencies in virtual environment..."
pip install pyinstaller strongdm

# Build standalone executable first
echo "Building standalone executable..."
pyinstaller --onefile --windowed --name "StrongDM-Manager" strongdm_manager.py

# Try to build app bundle (may not work on all macOS versions)
echo "Attempting to build macOS app bundle..."
pyinstaller --windowed --name "StrongDM-Manager-App" \
    --osx-bundle-identifier "com.strongdm.manager" \
    strongdm_manager.py

# Copy additional files to dist folder
echo "Copying additional files..."
cp requirements.txt dist/ 2>/dev/null || true
cp sample_*.csv dist/ 2>/dev/null || true
cp README.md dist/ 2>/dev/null || true
cp CLAUDE.md dist/ 2>/dev/null || true

# Create installation package structure
echo "Creating installation package..."
mkdir -p dist/StrongDM-Manager-Package

# Copy files that actually exist
if [ -f "dist/StrongDM-Manager" ]; then
    cp dist/StrongDM-Manager dist/StrongDM-Manager-Package/
    echo "✓ Standalone executable created"
fi

if [ -d "dist/StrongDM-Manager-App.app" ]; then
    cp -r dist/StrongDM-Manager-App.app dist/StrongDM-Manager-Package/StrongDM-Manager.app
    echo "✓ App bundle created"
else
    echo "⚠️ App bundle creation failed, but standalone executable is available"
fi

# Copy additional files
cp requirements.txt dist/StrongDM-Manager-Package/ 2>/dev/null || true
cp sample_*.csv dist/StrongDM-Manager-Package/ 2>/dev/null || true
cp README.md dist/StrongDM-Manager-Package/ 2>/dev/null || true

# Create installation script
cat > dist/StrongDM-Manager-Package/install.sh << 'EOF'
#!/bin/bash
echo "Installing StrongDM Manager..."

# Copy app to Applications folder if it exists
if [ -d "StrongDM-Manager.app" ]; then
    echo "Installing app bundle to /Applications..."
    cp -R StrongDM-Manager.app /Applications/ 2>/dev/null || {
        echo "Need admin rights to install to Applications folder:"
        sudo cp -R StrongDM-Manager.app /Applications/
    }
    echo "App bundle installed! You can find it in Applications."
fi

# Make standalone executable accessible
if [ -f "StrongDM-Manager" ]; then
    echo "Installing command-line executable..."
    cp StrongDM-Manager /usr/local/bin/ 2>/dev/null || {
        echo "Need admin rights to install to /usr/local/bin:"
        sudo cp StrongDM-Manager /usr/local/bin/
    }
    echo "Command-line executable installed! Run with: StrongDM-Manager"
fi

echo "Installation complete!"
EOF

chmod +x dist/StrongDM-Manager-Package/install.sh

# Create simple run script for local testing
cat > dist/StrongDM-Manager-Package/run.sh << 'EOF'
#!/bin/bash
echo "Starting StrongDM Manager..."

if [ -d "StrongDM-Manager.app" ]; then
    echo "Running app bundle..."
    open StrongDM-Manager.app
elif [ -f "StrongDM-Manager" ]; then
    echo "Running standalone executable..."
    ./StrongDM-Manager
else
    echo "No executable found!"
    exit 1
fi
EOF

chmod +x dist/StrongDM-Manager-Package/run.sh

# Create DMG if hdiutil is available
if command -v hdiutil &> /dev/null; then
    echo "Creating DMG installer..."
    rm -f dist/StrongDM-Manager.dmg 2>/dev/null || true
    hdiutil create -volname "StrongDM Manager" -srcfolder dist/StrongDM-Manager-Package -ov -format UDZO dist/StrongDM-Manager.dmg
    echo "✓ DMG created: dist/StrongDM-Manager.dmg"
fi

# Deactivate virtual environment
deactivate

# Remove build environment
rm -rf build_env

echo ""
echo "Build complete!"
echo ""
echo "Available files:"
if [ -f "dist/StrongDM-Manager" ]; then
    echo "✓ Standalone executable: dist/StrongDM-Manager"
fi
if [ -d "dist/StrongDM-Manager.app" ] || [ -d "dist/StrongDM-Manager-App.app" ]; then
    echo "✓ macOS App Bundle: dist/StrongDM-Manager*.app"
fi
if [ -f "dist/StrongDM-Manager.dmg" ]; then
    echo "✓ DMG installer: dist/StrongDM-Manager.dmg"
fi
echo "✓ Installation package: dist/StrongDM-Manager-Package/"
echo ""
echo "To test immediately:"
echo "cd dist/StrongDM-Manager-Package && ./run.sh"
echo ""
echo "To install:"
echo "1. Open the DMG: open dist/StrongDM-Manager.dmg"
echo "2. Or run: cd dist/StrongDM-Manager-Package && ./install.sh"