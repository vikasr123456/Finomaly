# Fraud & Anomaly Detection prototype — API + analyst dashboard image.
#
# Build from the REPOSITORY ROOT (the context is the repo root, not deploy/):
#   docker build -f deploy/Dockerfile -t fraud-platform:local .
#
# Run the offline test gate explicitly (CI should do this; the default target
# does NOT run tests so a demo build stays fast):
#   docker build -f deploy/Dockerfile --target test .
#
# This image contains no secrets. Every credential is injected at runtime from
# the deployment platform's secret store, and both services fail closed if a
# required token is unset or still a "<placeholder>".

FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /srv/app
# Dependencies first so code-only changes reuse the cached layer.
COPY deploy/requirements.lock.txt ./requirements.lock.txt
RUN pip install --no-cache-dir -r requirements.lock.txt

# --- Optional verification stage -------------------------------------------
# Binds only loopback, uses an in-memory/temporary database, and makes no
# provider calls (QWEN_MODE=mock). Proves the image contents pass the suite.
FROM base AS test
ENV QWEN_MODE=mock \
    DEMO_DB_PATH=/tmp/test-fraud.sqlite3 \
    DEMO_API_TOKEN=test-only-not-a-secret \
    DASHBOARD_TOKEN=test-only-not-a-secret
COPY app/ ./
RUN python -m unittest discover -s . -p "test_*.py" -v

# --- Runtime stage (default target) ----------------------------------------
FROM base AS runtime
COPY app/ ./

# Non-root, no writable paths outside the mounted data volume.
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /srv/data \
    && chown -R appuser:appuser /srv/app /srv/data
USER appuser

# SQLite lives on a mounted volume; it must be writable by appuser.
ENV DEMO_DB_PATH=/srv/data/fraud_demo.sqlite3 \
    QWEN_MODE=mock \
    PORT=8000
# Both ports are declared so PaaS platforms (e.g. Railway) can route either
# entrypoint from this one image: the api service runs fraud_demo:app on
# $PORT (8000 by default), the dashboard service sets APP_MODULE=dashboard:app
# with PORT=8001 — no image rebuild needed for either choice.
EXPOSE 8000 8001

# Liveness probe. /health returns no data and requires no credential.
HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
  CMD python -c "import os,urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8000')+'/health',timeout=4).status==200 else 1)"

# IMPORTANT: --workers 1. The prototype keeps cross-request state in one SQLite
# file guarded by an in-process lock and trains its Isolation Forest at import
# time. Multiple workers would duplicate the model in memory and break the
# single-writer assumption. Scale by sharding tenants across instances, or move
# to PostgreSQL plus a durable workflow engine before adding workers.
#
# Shell form (a single simple command, so the shell exec's python and signals
# are delivered) with two overridable knobs for PaaS deploys: platforms like
# Railway inject PORT at runtime and expect the process to listen on it, and
# APP_MODULE selects which service (api: fraud_demo:app, dashboard:
# dashboard:app) runs from this one image.
CMD python -m uvicorn "${APP_MODULE:-fraud_demo:app}" --host 0.0.0.0 --port "${PORT:-8000}" --workers 1
