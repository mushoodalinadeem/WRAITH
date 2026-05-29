import pandas as pd
from urllib.parse import urlparse
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from ml.train import _extract_features, _get_attack_type

df = pd.read_csv("data/csic_database.csv")

normal_samples = []
anom_samples = []

for idx, row in df.iterrows():
    raw_url = str(row.get("URL", ""))
    content = str(row.get("content", "")) if pd.notna(row.get("content", "")) else ""
    method = str(row.get("Method", "GET"))
    user_agent = str(row.get("User-Agent", ""))
    classification = row.get("classification", 0)
    
    parsed = urlparse(raw_url.split(" ")[0])
    url_path = parsed.path or "/"
    query_string = parsed.query or ""
    
    features = _extract_features(url_path, content, method, query_string, user_agent)
    
    if classification == 0:
        normal_samples.append((features, raw_url, content))
    else:
        anom_samples.append((features, raw_url, content))

print(f"Total Normal: {len(normal_samples)}, Total Anomalous: {len(anom_samples)}")

print("\nSample Normal Features:")
for f, url, c in normal_samples[:5]:
    print(f"Features: {f} | URL: {url} | Content: {c}")

print("\nSample Anomalous Features:")
for f, url, c in anom_samples[:5]:
    print(f"Features: {f} | URL: {url} | Content: {c}")
