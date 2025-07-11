@echo off
echo 🚀 Entity Toolkit - Windows Installer
echo ===================================

echo 📦 Checking prerequisites...

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python is not installed or not in PATH
    echo Please install Python 3.7+ from https://python.org
    pause
    exit /b 1
)

REM Check if Git is installed
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Git is not installed or not in PATH
    echo Please install Git from https://git-scm.com
    pause
    exit /b 1
)

echo ✅ Prerequisites found

echo 🐍 Setting up Python environment...

REM Create virtual environment
if not exist "entity-env" (
    python -m venv entity-env
    echo ✅ Virtual environment created
)

REM Activate virtual environment
call entity-env\Scripts\activate.bat

REM Upgrade pip
python -m pip install --upgrade pip

echo 📚 Installing Python dependencies...
pip install -r requirements.txt

if %errorlevel% neq 0 (
    echo ❌ Failed to install dependencies
    echo 🔧 Trying alternative installation...
    pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r requirements.txt
)

echo 🚀 Creating launcher script...

REM Create Windows batch launcher
echo @echo off > entity.bat
echo cd /d "%~dp0" >> entity.bat
echo call entity-env\Scripts\activate.bat >> entity.bat
echo python main.py >> entity.bat
echo pause >> entity.bat

echo ✅ Launcher created: entity.bat

echo 🧪 Testing installation...
python -c "import requests, rich, phonenumbers, whois; print('✅ All modules imported successfully')"

if %errorlevel% equ 0 (
    echo 🎉 Installation completed successfully!
    echo.
    echo 📋 Next steps:
    echo    • Run: entity.bat
    echo    • Read the documentation in README.md
    echo    • Check SETUP.md for detailed usage instructions
    echo.
    echo ⚖️  Remember: Use this tool ethically and legally!
) else (
    echo ❌ Installation test failed. Check the error messages above.
)

pause
