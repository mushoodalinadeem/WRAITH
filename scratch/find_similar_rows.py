import pandas as pd
from urllib.parse import urlparse

df = pd.read_csv("data/csic_database.csv")

matches = []
for idx, row in df.iterrows():
    raw_url = str(row.get("URL", ""))
    content = str(row.get("content", "")) if pd.notna(row.get("content", "")) else ""
    classification = row.get("classification", 0)
    parsed = urlparse(raw_url.split(" ")[0])
    url_path = parsed.path or "/"
    query_string = parsed.query or ""
    full_url = url_path + ("?" + query_string if query_string else "")
    
    if len(full_url) == 17 and url_path.count('/') == 2 and not content:
        matches.append((classification, raw_url))

print(f"Total matching rows in dataset: {len(matches)}")
print("\nFirst 10 matches:")
for c, url in matches[:10]:
    print(f"Classification: {c} | URL: {url}")
