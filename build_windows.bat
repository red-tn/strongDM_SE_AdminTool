@echo off
echo Building StrongDM Resource Manager for Windows...

REM Install required packages
pip install pyinstaller strongdm

REM Build executable
pyinstaller --onefile --windowed --name "StrongDM-Manager" strongdm_manager.py

REM Copy additional files to dist
copy requirements.txt dist\
copy example_resources.csv dist\
copy README.md dist\

echo Build complete! Executable available in dist\StrongDM-Manager.exe
pause
