import pandas as pd

data = {
    "Language": ["Python"] * 20 + ["Go"] * 20 + ["C"] * 20 + ["C++"] * 20 + ["Java"] * 20,
    "Code Snippet": [
        # Add the code snippets here...
    ],
    "Label": [
        # Add the labels here...
    ]
}

df = pd.DataFrame(data)
df.to_csv("synthetic_code_snippets.csv", index=False)
