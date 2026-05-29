import joblib
import math
import re

# Load model
data = joblib.load("ml/model.pkl")
clf = data["model"]
le = data["label_encoder"]

def extract_features(path, payload, method, query_string, user_agent):
    full_url = path + ("?" + query_string if query_string else "")
    url_length = float(len(full_url))
    payload_length = float(len(payload))

    payload_entropy = 0.0
    if payload:
        char_counts = {}
        for char in payload:
            char_counts[char] = char_counts.get(char, 0) + 1
        for count in char_counts.values():
            p = count / len(payload)
            payload_entropy -= p * math.log2(p)

    combined_text = full_url + " " + payload

    non_alphanum = sum(1 for c in payload if not c.isalnum() and not c.isspace())
    non_alphanum_ratio = float(non_alphanum) / len(payload) if payload else 0.0

    url_encoded_count = float(len(re.findall(r'%[0-9A-Fa-f]{2}', combined_text)))
    path_depth = float(path.count('/'))
    method_is_post = 1.0 if method.upper() == "POST" else 0.0
    user_agent_length = float(len(user_agent))

    return [
        url_length, payload_length, payload_entropy,
        non_alphanum_ratio, url_encoded_count, path_depth,
        method_is_post, user_agent_length
    ]

classes = le.inverse_transform(clf.classes_)

# Case 1: Normal path, short User Agent
feats1 = extract_features("/api/users", "", "GET", "id=123", "Mozilla/5.0")
probs1 = clf.predict_proba([feats1])[0]
pred1 = le.inverse_transform([clf.classes_[probs1.argmax()]])[0]
print(f"Short UA: prediction={pred1}, probabilities={dict(zip(classes, probs1))}")

# Case 2: Normal path, training User Agent
feats2 = extract_features("/api/users", "", "GET", "id=123", "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)")
probs2 = clf.predict_proba([feats2])[0]
pred2 = le.inverse_transform([clf.classes_[probs2.argmax()]])[0]
print(f"Training UA: prediction={pred2}, probabilities={dict(zip(classes, probs2))}")

# Case 3: Exactly a normal path from the dataset
feats3 = extract_features("/tienda1/index.jsp", "", "GET", "", "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)")
probs3 = clf.predict_proba([feats3])[0]
pred3 = le.inverse_transform([clf.classes_[probs3.argmax()]])[0]
print(f"Dataset Normal: prediction={pred3}, probabilities={dict(zip(classes, probs3))}")
