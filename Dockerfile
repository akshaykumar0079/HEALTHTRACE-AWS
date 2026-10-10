# HEALTH TRACE: one image serving the API, the WebSocket and the built UI.
# The same image also runs the synthetic log generator (demo sidecar).

# -- frontend build ---------------------------------------------------------------
FROM node:20-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# -- runtime ----------------------------------------------------------------------
FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HEALTHTRACE_ROOT=/app \
    PYTHONPATH=/app

WORKDIR /app
COPY backend/pyproject.toml backend/pyproject.toml
COPY backend/app backend/app
RUN pip install ./backend && rm -rf backend

COPY config.yaml ./
COPY generator ./generator
COPY --from=frontend /src/frontend/dist ./frontend/dist

RUN useradd --system --uid 10001 --home /app healthtrace \
    && mkdir -p /app/data/logs \
    && chown -R healthtrace /app/data
USER healthtrace

# Hosts such as Render inject PORT; local/compose runs default to 8000.
ENV PORT=8000
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=3 \
  CMD python -c "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/api/health' % os.environ.get('PORT','8000'), timeout=2).status == 200 else 1)"

# --proxy-headers: behind the ALB, trust X-Forwarded-* for the scheme (wss/https).
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips '*'"]
