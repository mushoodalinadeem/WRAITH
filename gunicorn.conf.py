"""Gunicorn settings for a single-process WRAITH deployment."""

bind = "0.0.0.0:5000"
workers = 1
worker_class = "gthread"
threads = 8
timeout = 120
graceful_timeout = 30
keepalive = 5
accesslog = "-"
errorlog = "-"
capture_output = True
preload_app = False
