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
