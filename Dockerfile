ARG SOURCE_DATE_EPOCH
FROM python:3.11.11-slim-bookworm@sha256:081075da77b2b55c23c088251026fb69a7b2bf92471e491ff5fd75c192fd38e5

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

# Install ODBC driver (required for optional SQL Server database backend).
# Debian packages come from the immutable snapshot paired with the base image;
# the Microsoft package is versioned and content-addressed.
RUN sed -i \
        -e 's|http://deb.debian.org/debian-security|http://snapshot.debian.org/archive/debian-security/20250407T000000Z|' \
        -e 's|http://deb.debian.org/debian|http://snapshot.debian.org/archive/debian/20250407T000000Z|' \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends \
        curl=7.88.1-10+deb12u12 \
        ca-certificates=20230311 \
        unixodbc=2.3.11-2+deb12u1 \
    && curl -fsSL \
        https://packages.microsoft.com/debian/12/prod/pool/main/m/msodbcsql18/msodbcsql18_18.6.2.1-1_amd64.deb \
        -o /tmp/msodbcsql18.deb \
    && echo '73438bb02bc26fb3d1c3d8cac36b3c26cb11629dbd0a3784990fc3235331b334  /tmp/msodbcsql18.deb' \
        | sha256sum -c - \
    && ACCEPT_EULA=Y apt-get install -y --no-install-recommends /tmp/msodbcsql18.deb \
    && rm -f /tmp/msodbcsql18.deb \
    && rm -rf /var/lib/apt/lists/* /var/log/apt/* /var/log/dpkg.log \
        /var/cache/ldconfig/aux-cache

COPY requirements.txt requirements.lock ./
RUN pip install --no-compile --require-hashes -r requirements.lock

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

# The transcript volume's mount point must exist in the image, owned by the
# runtime user. Docker copies the image directory's ownership into an empty
# named volume on first mount; with no directory to copy from it creates the
# mount point as root:root, and the service — running as umai, under
# `read_only: true`, `cap_drop: ALL` and `no-new-privileges` — cannot chown it
# at runtime and cannot be given the capability to. Every `full_session`
# ingest then fails with `PermissionError: /var/lib/umai/transcripts/<tenant>`.
# Keep this above `USER umai`: it is the only place the ownership can be set.
RUN mkdir -p /var/lib/umai/transcripts \
    && chown -R umai:umai /var/lib/umai

USER umai

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')" || exit 1

CMD ["./docker-entrypoint.sh"]
