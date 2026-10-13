#!/usr/bin/env bash
set -e

echo "=================================================="
echo "🛡️  CTEM Platform - Docker Launcher"
echo "=================================================="

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker is not installed or not in your PATH."
    echo "Please install Docker Desktop from https://www.docker.com/products/docker-desktop/"
    exit 1
fi

# Check if .env file exists, otherwise copy from template
if [ ! -f .env ]; then
    echo "⚠️  No .env file found in root. Generating from .env.example..."
    cp .env.example .env
    echo "👉 Please edit the '.env' file with your SUPABASE_URL and SUPABASE_KEY before launching."
    echo "Opening .env for editing..."
    exit 0
fi

# Source .env to check if SUPABASE_URL is set
if grep -q "SUPABASE_URL=https://your-project-id.supabase.co" .env || grep -q "SUPABASE_URL=$" .env; then
    echo "⚠️  Warning: SUPABASE_URL in .env appears to be unconfigured."
    echo "Please set your actual Supabase URL and Key in '.env'."
    read -p "Do you want to continue anyway? [y/N]: " choice
    if [[ ! "$choice" =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "🚀 Building and starting containers in detached mode..."
docker compose up --build -d

echo ""
echo "=================================================="
echo "✅ CTEM Platform is running!"
echo "=================================================="
echo "🌐 Frontend Dashboard: http://localhost:3000"
echo "💥 Blast Radius View:  http://localhost:3000/blast-radius"
echo "🔌 Backend REST API:   http://localhost:8000"
echo "📖 API Documentation:  http://localhost:8000/docs"
echo "=================================================="
echo ""
echo "To view live logs:    docker compose logs -f"
echo "To stop platform:     docker compose down"
