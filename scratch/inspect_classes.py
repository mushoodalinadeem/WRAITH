import joblib
import pandas as pd

# Load model
data = joblib.load("ml/model.pkl")
clf = data["model"]
le = data["label_encoder"]

print("LabelEncoder classes:", le.classes_)
print("Classifier classes:", clf.classes_)
print("Classifier classes decoded:", le.inverse_transform(clf.classes_))
