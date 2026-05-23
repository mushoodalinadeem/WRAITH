import requests
import json

URL = "http://127.0.0.1:5000/classify"

tests = [
    {
        "name": "Benign CSIC Path (index.jsp)",
        "data": {
            "path": "/tienda1/index.jsp",
            "method": "GET",
            "query_string": "",
            "payload": "",
            "user_agent": "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)"
        }
    },
    {
        "name": "Benign CSIC Path (anadir.jsp)",
        "data": {
            "path": "/tienda1/publico/anadir.jsp",
            "method": "GET",
            "query_string": "",
            "payload": "",
            "user_agent": "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)"
        }
    },
    {
        "name": "Anomalous CSIC Path (publico~)",
        "data": {
            "path": "/tienda1/publico~",
            "method": "GET",
            "query_string": "",
            "payload": "",
            "user_agent": "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)"
        }
    },
    {
        "name": "Normal Honey Route (api/search)",
        "data": {
            "path": "/api/search",
            "method": "GET",
            "query_string": "",
            "payload": "",
            "user_agent": "Mozilla/5.0"
        }
    },
    {
        "name": "SQL Injection Bypassing Fallback",
        "data": {
            "path": "/api/search",
            "method": "GET",
            "query_string": "id=1'or'1'='1",
            "payload": "",
            "user_agent": "Mozilla/5.0"
        }
    },
    {
        "name": "URL-Encoded SQL Injection Bypassing Fallback",
        "data": {
            "path": "/api/search",
            "method": "GET",
            "query_string": "id=1%27or%271%27%3D%271",
            "payload": "",
            "user_agent": "Mozilla/5.0"
        }
    },
    {
        "name": "XSS Bypassing Fallback",
        "data": {
            "path": "/api/search",
            "method": "POST",
            "query_string": "",
            "payload": "<img src=x onmouseover=prompt(1)>", 
            "user_agent": "Mozilla/5.0"
        }
    }
]

print("Running API classification tests against WRAITH honeypot...\n")
for t in tests:
    print(f"--- Test Case: {t['name']} ---")
    print(f"Request Data: {json.dumps(t['data'], indent=2)}")
    try:
        response = requests.post(URL, json=t["data"])
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    except Exception as e:
        print(f"Error connecting to server: {e}")
    print("\n" + "="*50 + "\n")
