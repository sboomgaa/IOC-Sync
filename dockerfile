FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY defender_ioc_export.py .
COPY config.yaml.example .
COPY README.md .

RUN mkdir -p /app/exports

ENTRYPOINT ["python", "/app/defender_ioc_export.py"]
