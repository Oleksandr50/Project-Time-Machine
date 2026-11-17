FROM python:3.11-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PTM_CONFIG=/config/settings.json PTM_HOST=127.0.0.1 PTM_PORT=13011 PTM_MANAGED_ID=container PTM_CONTAINER=1
LABEL org.opencontainers.image.title="Project Time Machine" org.opencontainers.image.version="0.7.6"
WORKDIR /opt/project-time-machine
COPY requirements.lock ./requirements.lock
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.lock
COPY app/ ./app/
USER 1000:1000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD python -c "import os,json,urllib.request; r=json.load(urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://127.0.0.1:'+os.environ.get('PTM_PORT','13011')+'/healthz',timeout=3)); assert r.get('status')=='ok' and r.get('instance')==os.environ['PTM_MANAGED_ID']"
CMD ["python", "-B", "-m", "app"]
