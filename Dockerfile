FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml ./
COPY requirements-api.lock requirements-agent.lock ./

FROM base AS api
RUN pip install --no-cache-dir -r requirements-api.lock && useradd --uid 10001 --create-home lanmark \
    && mkdir /data && chown lanmark:lanmark /data
COPY lanmark ./lanmark
RUN pip install --no-cache-dir --no-deps .
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "lanmark.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log"]

FROM base AS agent
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping libpcap0.8 \
    && rm -rf /var/lib/apt/lists/* && pip install --no-cache-dir -r requirements-agent.lock
COPY lanmark ./lanmark
RUN pip install --no-cache-dir --no-deps .
CMD ["python", "-m", "lanmark.agent"]
