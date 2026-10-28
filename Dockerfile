FROM python:3.11-slim

# Create user first to anchor the cache layer
RUN useradd -m -s /bin/bash wraith

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create necessary runtime directories
RUN mkdir -p /app/data /app/ml && chown -R wraith:wraith /app

# COPY with ownership flags prevents layer duplication and speeds up builds
COPY --chown=wraith:wraith . .

VOLUME ["/app/data"]

USER wraith

EXPOSE 5000
CMD ["gunicorn", "--config", "gunicorn.conf.py", "main:app"]