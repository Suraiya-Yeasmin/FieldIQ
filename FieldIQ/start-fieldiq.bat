@echo off
cd /d "%~dp0backend"
if not exist .env (
  echo ERROR: backend\.env not found. Copy backend\.env.example to backend\.env and configure PostgreSQL first.
  pause
  exit /b 1
)
if not exist node_modules (
  echo Installing dependencies...
  call npm install
  if errorlevel 1 pause & exit /b 1
)
call npm start
pause
