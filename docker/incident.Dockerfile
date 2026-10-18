FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY requirements-incident.txt ./
RUN python -m pip install --no-cache-dir -r requirements-incident.txt \
    && groupadd --gid 10001 secureincident \
    && useradd --uid 10001 --gid 10001 --no-create-home secureincident \
    && mkdir -p /var/lib/secureincident /run/secureincident/public \
    && chown -R 10001:10001 /var/lib/secureincident /run/secureincident
COPY services/__init__.py services/__init__.py
COPY services/incident_service/ services/incident_service/
USER 10001:10001
EXPOSE 8001
CMD ["python", "-m", "uvicorn", "services.incident_service.app:app", "--host", "0.0.0.0", "--port", "8001"]
