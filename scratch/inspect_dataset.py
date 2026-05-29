import pandas as pd
df = pd.read_csv("data/csic_database.csv")
print("Columns:")
print(df.columns.tolist())
print("\nFirst column unique values:")
print(df.iloc[:, 0].value_counts())
print("\n'classification' column unique values:")
print(df['classification'].value_counts())
print("\nSample anomalous row:")
anom = df[df['classification'] == 1].head(3)
for idx, row in anom.iterrows():
    print(f"Row {idx}:")
    print(dict(row))
