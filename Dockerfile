FROM python:3.11-slim

# ── OCI image labels ─────────────────────────────────────────────────────────
LABEL org.opencontainers.image.title="UMAI Enterprise Service"
LABEL org.opencontainers.image.description="UMAI Platform REST API — policy management, guardrail evaluation proxy, and audit layer"
LABEL org.opencontainers.image.vendor="UMAI AI"
LABEL org.opencontainers.image.licenses="Proprietary"
LABEL org.opencontainers.image.documentation="https://docs.umai.ai"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install ODBC driver (required for optional SQL Server database backend)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        gnupg \
        ca-certificates \
        unixodbc \
        unixodbc-dev \
        gcc \
        g++ \
    && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc \
        | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" \
        > /etc/apt/sources.list.d/mssql-release.list \
    && apt-get update \
    && ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY alembic.ini .
COPY migrations ./migrations
COPY scripts ./scripts
COPY seed.py .
COPY docker-entrypoint.sh ./docker-entrypoint.sh

# Run as non-root user
RUN groupadd -r umai && useradd -r -g umai -d /app -s /sbin/nologin umai \
    && chown -R umai:umai /app \
    && chmod +x /app/docker-entrypoint.sh
USER umai

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')" || exit 1

CMD ["./docker-entrypoint.sh"]
