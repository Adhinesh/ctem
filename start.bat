@echo off
setlocal enabledelayedexpansion

echo ==================================================
echo CTEM Platform - Windows Docker Launcher
echo ==================================================

REM Check if Docker is installed
where docker >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Docker is not installed or not in PATH.
    echo Please install Docker Desktop for Windows: https://www.docker.com/products/docker-desktop/
    pause
    exit /b 1
)

REM Check if .env file exists
if not exist .env (
    echo [WARNING] No .env file found. Creating from .env.example...
    copy .env.example .env
    echo [ACTION REQUIRED] Please edit the .env file with your SUPABASE_URL and SUPABASE_KEY.
    notepad .env
    echo Once saved, run this script again.
    pause
    exit /b 0
)

echo [INFO] Building and starting Docker containers...
docker compose up --build -d

if %errorlevel% equ 0 (
    echo.
    echo ==================================================
    echo [SUCCESS] CTEM Platform is running!
    echo ==================================================
    echo Frontend Dashboard: http://localhost:3000
    echo Blast Radius View:  http://localhost:3000/blast-radius
    echo Backend API:        http://localhost:8000
    echo API Docs (Swagger): http://localhost:8000/docs
    echo ==================================================
    echo.
    echo View logs with:    docker compose logs -f
    echo Stop with:         docker compose down
) else (
    echo [ERROR] Failed to start containers. Check Docker Desktop is running.
)

pause
