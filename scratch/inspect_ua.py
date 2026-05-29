import pandas as pd
df = pd.read_csv("data/csic_database.csv")
print("User-Agent value counts:")
print(df['User-Agent'].value_counts())
