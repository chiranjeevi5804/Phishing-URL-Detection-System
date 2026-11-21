# Sentinel — Phishing URL Detection System

A responsive Flask + Scikit-learn cybersecurity dashboard that extracts URL features and classifies URLs as legitimate or potentially phishing. Includes SQLite scan history, risk visualization, analytics, and CSV export.

## Quick start (Windows PowerShell)

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
py ml/generate_demo_data.py
py ml/train.py
py app.py
```

Open http://127.0.0.1:5000

If PowerShell blocks activation, skip it and run `.venv\Scripts\python.exe` instead of `py` for each subsequent command.

## Real labeled dataset

Replace `data/urls.csv` with a labeled dataset containing `url,label` (0 = legitimate, 1 = phishing). Then run `py ml/train.py` and restart Flask. Or pass a path: `py ml/train.py path/to/your_data.csv`.

**Critical caveat:** The included dataset generator creates synthetic examples, not a real phishing benchmark. High evaluation scores on synthetic data do not establish real-world accuracy. For serious evaluation, obtain a trustworthy real-world dataset with documented labels, deduplicate URLs, split by hostname/time to reduce leakage, and assess on an independent set. No model can guarantee a URL is safe.

## Security and architecture

- URL parsing and lexical feature extraction only; scanner does **not** visit submitted URLs.
- Random Forest classifier, held-out 80/20 evaluation, saved model.
- SQLite-backed scan history, JSON APIs `/api/scan`, `/api/stats`, and `/api/export`.
- HTML escaping on the dashboard to avoid injecting submitted URLs.
- Development-only local Flask server. Do not deploy publicly without authentication, CSRF/rate limiting as appropriate, privacy policy, and production WSGI configuration.
- Never load a model.joblib from an untrusted source.

## Stack

Python, Pandas, Scikit-learn, Flask, SQLite, HTML, CSS, JavaScript.
