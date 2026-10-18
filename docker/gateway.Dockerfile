FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY requirements-gateway.txt ./
RUN python -m pip install --no-cache-dir -r requirements-gateway.txt \
    && groupadd --gid 10001 secureincident \
    && useradd --uid 10001 --gid 10001 --no-create-home secureincident \
    && mkdir -p /run/secureincident/private /run/secureincident/public \
    && chown -R 10001:10001 /run/secureincident
COPY services/__init__.py services/__init__.py
COPY services/gateway/ services/gateway/
COPY scripts/docker_init_keys.py scripts/docker_init_keys.py
USER 10001:10001
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "services.gateway.app:app", "--host", "0.0.0.0", "--port", "8000"]
