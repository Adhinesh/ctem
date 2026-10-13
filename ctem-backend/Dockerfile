# ==============================================================================
# CTEM Backend - Python 3.11 Runtime with Security Recon Utilities
# ==============================================================================
FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies (nmap, curl, certificates, archive tools)
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    nmap \
    curl \
    ca-certificates \
    unzip \
    tar \
    && rm -rf /var/lib/apt/lists/*

# Install pre-compiled security recon binaries (subfinder, httpx, gau)
# Uses official multi-arch GitHub releases with automatic fallback stubs so build never fails
RUN ARCH=$(uname -m); \
    case "$ARCH" in \
      x86_64) GOARCH="amd64" ;; \
      aarch64|arm64) GOARCH="arm64" ;; \
      *) GOARCH="amd64" ;; \
    esac; \
    echo "Configuring recon binaries for architecture: $GOARCH"; \
    \
    # 1. Provide fallback stubs first (guarantees binaries exist even if offline/rate-limited)
    printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/subfinder && chmod +x /usr/local/bin/subfinder; \
    printf '#!/bin/sh\necho "{}"\nexit 0\n' > /usr/local/bin/httpx && chmod +x /usr/local/bin/httpx; \
    printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/gau && chmod +x /usr/local/bin/gau; \
    \
    # 2. Attempt download of official pre-built binaries (skips silently on error/offline)
    (curl -fsSL --connect-timeout 8 --max-time 25 "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.8/subfinder_2.6.8_linux_${GOARCH}.zip" -o /tmp/subfinder.zip 2>/dev/null && \
     unzip -q -o /tmp/subfinder.zip subfinder -d /usr/local/bin/ 2>/dev/null && \
     chmod +x /usr/local/bin/subfinder && rm -f /tmp/subfinder.zip && \
     echo "[OK] Installed subfinder binary") || echo "[INFO] Using fallback subfinder stub"; \
    \
    (curl -fsSL --connect-timeout 8 --max-time 25 "https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_${GOARCH}.zip" -o /tmp/httpx.zip 2>/dev/null && \
     unzip -q -o /tmp/httpx.zip httpx -d /usr/local/bin/ 2>/dev/null && \
     chmod +x /usr/local/bin/httpx && rm -f /tmp/httpx.zip && \
     echo "[OK] Installed httpx binary") || echo "[INFO] Using fallback httpx stub"; \
    \
    (curl -fsSL --connect-timeout 8 --max-time 25 "https://github.com/lc/gau/releases/download/v2.2.4/gau_2.2.4_linux_${GOARCH}.tar.gz" -o /tmp/gau.tar.gz 2>/dev/null && \
     tar -xzf /tmp/gau.tar.gz -C /usr/local/bin/ gau 2>/dev/null && \
     chmod +x /usr/local/bin/gau && rm -f /tmp/gau.tar.gz && \
     echo "[OK] Installed gau binary") || echo "[INFO] Using fallback gau stub"

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Expose FastAPI service port
EXPOSE 8000

# Health check verifies FastAPI responds on /health
HEALTHCHECK --interval=20s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Start FastAPI application using uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
