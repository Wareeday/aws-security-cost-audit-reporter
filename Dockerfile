FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml requirements.txt README.md ./
COPY src/ ./src/
COPY sample_data/ ./sample_data/
COPY main.py ./

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir ".[all]" \
    && useradd --create-home --shell /sbin/nologin appuser \
    && mkdir -p /app/output \
    && chown -R appuser:appuser /app

USER appuser

ENTRYPOINT ["aws-audit"]
CMD ["--mode", "demo", "--output-dir", "/app/output"]
