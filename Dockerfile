FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m -s /bin/bash wraith && \
    chown -R wraith:wraith /app && \
    mkdir -p /app/data /app/ml && \
    chown -R wraith:wraith /app/data /app/ml

VOLUME ["/app/data"]

USER wraith

EXPOSE 5000
CMD ["python3", "main.py"]