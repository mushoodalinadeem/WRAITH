"""
app/classifier.py — Machine Learning classification stub.

This file acts as a placeholder for the Week 3 ML integration.
Currently, it returns "Normal" and 0.0 confidence so the pipeline
can run without crashing.
"""

def classify_request(request_data: dict) -> tuple:
    """
    Extracts features and predicts attack type using the trained ML model.
    
    Args:
        request_data (dict): The logged request containing path, payload, headers, etc.
        
    Returns:
        tuple: (attack_type: str, confidence: float)
    """
    # TODO (Week 3): 
    # 1. Load model.pkl and vectorizer.pkl
    # 2. Extract the 8 mathematical features from request_data
    # 3. Run model.predict_proba()
    # 4. Return the predicted attack type and confidence score
    
    # Placeholder return to keep the WRAITH engine running
    return ("Normal", 0.0)
