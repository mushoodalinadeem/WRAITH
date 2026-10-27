# WRAITH Honeypot

WRAITH is an advanced, high-performance honeypot designed to intercept, log, and classify malicious web traffic in real-time.

## Architecture Limitations & Production Deployment

WRAITH uses an asynchronous, thread-safe memory queue (`collections.deque`) to buffer incoming attacks during HTTP floods. Because this queue and the rate-limiting sliding windows reside in local application memory, **WRAITH must be run as a single process**.

### Local Development

When running locally via `main.py`, the Flask auto-reloader has been explicitly disabled (`use_reloader=False`) to prevent it from spinning up two parallel background workers.

```bash
python3 main.py
```

### Production (Gunicorn)

If deploying WRAITH behind a production WSGI server like Gunicorn, **you MUST restrict it to exactly one worker**. Use the provided `gunicorn.conf.py` which configures a single worker with 8 threads:

```bash
gunicorn --config gunicorn.conf.py main:app
```

Running multiple workers will fragment the logging queue, corrupt the rate-limiting counters, and cause database race conditions.

## Container Deployment & Persistence

Before building the Docker image, ensure you have trained the Random Forest model locally so the serialized classifier `ml/model.pkl` is packaged inside the container:

```bash
# 1. Train the model locally (requires CSIC dataset files in ml/data/)
python3 ml/train.py

# 2. Build the Docker container
docker build -t wraith .
```

### Training Data

The training pipeline (`ml/train.py`) requires the following dataset files in `ml/data/`:
- `csic_database.csv` — CSIC 2010 HTTP dataset
- `payload_train.csv` / `payload_test.csv` — HttpParams payload datasets

These files are not included in the repository due to size. Obtain them from the CSIC 2010 and HttpParams public datasets, then place them in `ml/data/` before running `ml/train.py`.

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

**Note:** The container runs Flask's development server directly (`python3 main.py`). For production container deployments, override the entrypoint to use gunicorn:

```bash
docker run -d \
  -p 5000:5000 \
  -v wraith_data:/app/data \
  --name wraith-instance \
  wraith \
  gunicorn --config gunicorn.conf.py main:app
```

## Configuration

All runtime configuration is controlled via environment variables. See `config.py` for the full list. Critical production settings:

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Yes (prod) | Unique 32+ char secret for session signing |
| `DASHBOARD_PASSWORD` / `DASHBOARD_PASSWORD_HASH` | Yes (prod) | Admin dashboard authentication |
| `WRAITH_ENV` | No | `development` / `production` / `test` |
| `WRAITH_DB_PATH` | No | Custom SQLite path (default: `data/wraith.db`) |
| `WRAITH_MODEL_PATH` | No | Custom model path (default: `ml/model.pkl`) |

The `config.py` validator will refuse to start in production if placeholder secrets are detected.

## Detection Layers

| Layer | Status | Capabilities |
|-------|--------|--------------|
| Rule | Active | HTTP Flood, Directory Enumeration, Web Brute Force |
| Fallback | Active | SQLi, XSS, CRLF Injection, File Disclosure, Buffer Overflow |
| ML (Random Forest) | Optional | CSIC 2010 trained classifier — requires `ml/model.pkl` |

The ML layer activates automatically when a trained `model.pkl` is present at startup.

## Endpoints

**Honeypot (public):**
- Dynamic catch-all — logs and classifies all unknown paths

**Operator (authentication required):**
- `GET  /dashboard` — forensic console
- `GET  /logs` — recent log entries
- `GET  /logs/<id>` — forensic detail
- `POST /classify` — on-demand classification
- `GET  /stream` — SSE live stream
- `GET  /stats` — summary statistics
- `GET  /healthz` — liveness probe