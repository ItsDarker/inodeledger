@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\pythonw.exe" (
  echo Please create .venv and install this project first. See README.md.
  pause
  exit /b 1
)
start "InodeLedger" ".venv\Scripts\pythonw.exe" -m inodeledger gui
