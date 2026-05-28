# WRAITH Honeypot

WRAITH is an advanced, high-performance honeypot designed to intercept, log, and classify malicious web traffic in real-time.

## Architecture Limitations & Production Deployment
WRAITH uses an asynchronous, thread-safe memory queue (`collections.deque`) to buffer incoming attacks during HTTP floods. Because this queue and the rate-limiting sliding windows reside in local application memory, **WRAITH must be run as a single process**.

### Local Development
When running locally via `main.py`, the Flask auto-reloader has been explicitly disabled (`use_reloader=False`) to prevent it from spinning up two parallel background workers.

### Production (Gunicorn)
If deploying WRAITH behind a production WSGI server like Gunicorn, **you MUST restrict it to exactly one worker**:

```bash
gunicorn -w 1 main:app
```

Running multiple workers will fragment the logging queue, corrupt the rate-limiting counters, and cause database race conditions.

## Container Deployment & Persistence

Before building the Docker image, ensure you have trained the Random Forest model locally so the serialized classifier `ml/model.pkl` is packaged inside the container:

```bash
# 1. Train the model locally
python3 ml/train.py

# 2. Build the Docker container
docker build -t wraith .
```

### Forensic Log Persistence

Since WRAITH records security audits and live honeypot telemetry in `/app/data/wraith.db` (SQLite), you must mount a persistent volume when launching the container. Without a mounted volume, all logs will be wiped if the container restarts or is replaced.

Run the container by mounting a Docker volume to `/app/data`:

```bash
docker run -d \
  -p 5000:5000 \
  -v wraith_data:/app/data \
  --name wraith-instance \
  wraith
```
