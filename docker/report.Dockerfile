FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY requirements-report.txt ./
COPY packages/incident_formatter/ packages/incident_formatter/
RUN python -m pip install --no-cache-dir -r requirements-report.txt \
    && groupadd --gid 10001 secureincident \
    && useradd --uid 10001 --gid 10001 --no-create-home secureincident \
    && mkdir -p /run/secureincident/public \
    && chown -R 10001:10001 /run/secureincident
COPY services/__init__.py services/__init__.py
COPY services/report_service/ services/report_service/
USER 10001:10001
EXPOSE 8002
CMD ["python", "-m", "uvicorn", "services.report_service.app:app", "--host", "0.0.0.0", "--port", "8002"]
