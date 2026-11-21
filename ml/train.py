from pathlib import Path
import json
import sys
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from features import extract_features

ROOT = Path(__file__).resolve().parents[1]
source = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / 'data' / 'urls.csv'
if not source.exists():
    raise SystemExit('Dataset missing. Run python ml/generate_demo_data.py first, or supply a real labeled CSV path.')
df = pd.read_csv(source).dropna(subset=['url', 'label']).drop_duplicates(subset=['url'])
if not {'url', 'label'}.issubset(df.columns):
    raise SystemExit('CSV must contain url,label columns; label 0=legitimate, 1=phishing.')
df['label'] = pd.to_numeric(df['label'], errors='raise')
if not set(df.label.unique()).issubset({0, 1}) or df.label.nunique() != 2:
    raise SystemExit('Labels must include both 0 (legitimate) and 1 (phishing).')
features = []
labels = []
for url, label in zip(df.url, df.label):
    try:
        features.append(extract_features(url))
        labels.append(int(label))
    except ValueError:
        continue
if len(features) < 30:
    raise SystemExit('At least 30 valid labeled URLs required.')
X = pd.DataFrame(features)
y = pd.Series(labels)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
model = RandomForestClassifier(n_estimators=200, min_samples_leaf=2, class_weight='balanced', random_state=42, n_jobs=-1)
model.fit(X_train, y_train)
pred = model.predict(X_test)
metrics = {'accuracy': round(accuracy_score(y_test, pred), 4), 'precision': round(precision_score(y_test, pred, zero_division=0), 4), 'recall': round(recall_score(y_test, pred, zero_division=0), 4), 'f1': round(f1_score(y_test, pred, zero_division=0), 4), 'confusion_matrix': confusion_matrix(y_test, pred).tolist(), 'training_rows': len(X_train), 'test_rows': len(X_test), 'dataset': source.name, 'demo_data': source.name == 'urls.csv'}
joblib.dump({'model': model, 'features': list(X.columns)}, ROOT / 'ml' / 'model.joblib')
(ROOT / 'ml' / 'metrics.json').write_text(json.dumps(metrics, indent=2), encoding='utf-8')
print(json.dumps(metrics, indent=2))
if metrics['demo_data']:
    print('WARNING: Metrics are on synthetic demonstration data and do NOT indicate real-world detection accuracy.')
