import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib

# 1. The Dataset (Mock data for training)
# In real life, you would load a large CSV file from Kaggle here.
# label: 1 = Malicious/Phishing, 0 = Safe
data = {
    'url': [
        'http://secure-update-paypal.com/login', 
        'https://google.com', 
        'http://192.168.1.1/update', 
        'https://amazon.com',
        'http://fedex-tracking-alert.top/pkg', 
        'https://github.com',
        'https://apple-support-verify.xyz'
    ],
    'label': [1, 0, 1, 0, 1, 0, 1] 
}
df = pd.DataFrame(data)

# 2. Feature Engineering (Converting Text to Numbers)
def extract_features(url):
    return [
        len(url),                                   # Feature 1: Total length of URL
        url.count('.'),                             # Feature 2: Number of dots
        url.count('-'),                             # Feature 3: Number of hyphens
        1 if 'http://' in url else 0,               # Feature 4: Is it unsecure HTTP? (1=Yes, 0=No)
        1 if '.top' in url or '.xyz' in url else 0  # Feature 5: Does it use a sketchy domain?
    ]

# 3. Prepare the Training Data
X = [extract_features(url) for url in df['url']] # X is our feature matrix
y = df['label'].values                           # y is our target labels

# 4. Train the Machine Learning Model
# We use a Random Forest, a powerful algorithm for tabular data
model = RandomForestClassifier(n_estimators=50, random_state=42)
model.fit(X, y)

# 5. Save the "Brain" to the api folder
joblib.dump(model, 'api/phishing_model.pkl') # Saves one folder up, inside api/
print("✅ Model successfully trained and saved into the api/ folder!")