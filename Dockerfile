FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates nodejs npm \
 && rm -rf /var/lib/apt/lists/*
# Gitleaks (pinned release)
RUN curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz | tar -xz -C /usr/local/bin gitleaks
# Semgrep in its own venv so its pins don't clash with THRYV's
RUN python -m venv /opt/sg && /opt/sg/bin/pip install semgrep && ln -s /opt/sg/bin/semgrep /usr/local/bin/semgrep
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
RUN chmod +x start.sh
ENV THRYV_HOST=0.0.0.0 THRYV_DB=/data/thryv.db THRYV_ARTIFACTS=/data/artifacts THRYV_REPO_ROOT=/data/repos
CMD ["./start.sh"]
