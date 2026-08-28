"""
Cyber Shield Enterprise ML Training Pipeline
--------------------------------------------
Trains a high-performance Machine Learning classifier using the provided dataset
(malicious_phish.csv - 651,191 real-world URLs).
"""

import os
import sys
import csv
import re
import time
import random
from typing import Tuple, List

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

# High-profile verified benign domains
TOP_BENIGN_DOMAINS = [
    "google.com", "google.co.in", "google.co.uk", "google.com.br", "gmail.com", "youtube.com",
    "wikipedia.org", "en.wikipedia.org", "wikimedia.org",
    "github.com", "github.io", "gitlab.com",
    "microsoft.com", "live.com", "outlook.com", "office.com", "azure.com",
    "apple.com", "icloud.com", "itunes.com",
    "amazon.com", "amazon.in", "amazon.co.uk", "aws.amazon.com",
    "facebook.com", "instagram.com", "whatsapp.com", "twitter.com", "x.com", "linkedin.com",
    "reddit.com", "netflix.com", "spotify.com", "stackoverflow.com", "cnn.com", "bbc.com"
]

def clean_url_tokens(text: str) -> str:
    """Tokenize URL into meaningful semantic word components."""
    t = text.strip().lower()
    t = re.sub(r'^https?://', '', t)
    t = re.sub(r'^www\.', '', t)
    tokens = re.split(r'[/_?=&.-]', t)
    meaningful = [tok for tok in tokens if len(tok) > 1 and tok not in ['com', 'org', 'net', 'html', 'php', 'htm', 'index', 'asp']]
    return ' '.join(meaningful)

def find_dataset_file() -> str:
    search_paths = [
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "malicious_phish.csv"),
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "malicious_phish.csv"),
        os.path.join(os.getcwd(), "malicious_phish.csv"),
        os.path.join(os.getcwd(), "..", "malicious_phish.csv"),
        "c:\\Users\\2007s\\OneDrive\\Documents\\CyberShieldWeb\\malicious_phish.csv"
    ]
    for path in search_paths:
        abs_path = os.path.abspath(path)
        if os.path.exists(abs_path):
            return abs_path
    return ""

def load_dataset(csv_path: str, max_samples_per_class: int = 75000) -> Tuple[List[str], List[int]]:
    random.seed(42)
    benign_raw = []
    malicious_raw = []

    print(f"[*] Reading dataset: {csv_path}")
    with open(csv_path, mode='r', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        header = next(reader, None)
        for row in reader:
            if len(row) >= 2:
                url = row[0].strip()
                label_type = row[1].strip().lower()
                if label_type == "benign":
                    benign_raw.append(url)
                elif label_type in ["phishing", "malware", "defacement"]:
                    malicious_raw.append(url)

    print(f"[*] Loaded {len(benign_raw):,} Benign URLs and {len(malicious_raw):,} Malicious URLs.")

    sampled_benign = random.sample(benign_raw, min(max_samples_per_class, len(benign_raw)))
    sampled_malicious = random.sample(malicious_raw, min(max_samples_per_class, len(malicious_raw)))

    X = []
    y = []

    for u in sampled_benign:
        X.append(clean_url_tokens(u))
        y.append(0)

    # Ensure top benign domains are reinforced
    for d in TOP_BENIGN_DOMAINS * 50:
        X.append(clean_url_tokens(d))
        y.append(0)

    for u in sampled_malicious:
        X.append(clean_url_tokens(u))
        y.append(1)

    print(f"[*] Prepared balanced training corpus of {len(X):,} total samples.")
    return X, y

def train_and_export(max_samples: int = 75000):
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.naive_bayes import MultinomialNB
        from sklearn.pipeline import Pipeline
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
        import joblib
    except ImportError:
        print("[!] scikit-learn or joblib not installed. Run: pip install scikit-learn joblib")
        return False

    print("====================================================================")
    print("      CYBER SHIELD ENTERPRISE ML MODEL TRAINING PIPELINE           ")
    print("====================================================================")

    csv_path = find_dataset_file()
    if not csv_path:
        print("[!] Error: malicious_phish.csv not found.")
        return False

    X, y = load_dataset(csv_path, max_samples_per_class=max_samples)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"[*] Splitting: {len(X_train):,} Train samples | {len(X_test):,} Test samples")
    print("[*] Extracting word n-grams (1-3) with TF-IDF Vectorizer and fitting Naive Bayes...")

    start_time = time.time()

    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            ngram_range=(1, 3),
            max_features=45000,
            sublinear_tf=True
        )),
        ('clf', MultinomialNB(alpha=0.08))
    ])

    pipeline.fit(X_train, y_train)
    duration = round(time.time() - start_time, 2)

    print(f"[✓] Model training completed in {duration} seconds!")
    print("\n[*] Evaluating model on held-out test split...")
    y_pred = pipeline.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=["Benign (Safe)", "Malicious"], digits=4)
    cm = confusion_matrix(y_test, y_pred)

    print("--------------------------------------------------------------------")
    print(f"  Overall Test Accuracy: {round(accuracy * 100, 2)}%")
    print("--------------------------------------------------------------------")
    print(report)
    print(f"Confusion Matrix:\n  True Negatives:  {cm[0][0]:<6} | False Positives: {cm[0][1]}")
    print(f"  False Negatives: {cm[1][0]:<6} | True Positives:  {cm[1][1]}")
    print("--------------------------------------------------------------------")

    models_dir = os.path.join(os.path.dirname(__file__), "models")
    os.makedirs(models_dir, exist_ok=True)
    model_path = os.path.join(models_dir, "phishing_classifier.joblib")

    print(f"[*] Exporting fitted model to: {model_path}")
    joblib.dump(pipeline, model_path, compress=3)
    file_size_mb = round(os.path.getsize(model_path) / (1024 * 1024), 2)
    print(f"[✓] Successfully saved production model ({file_size_mb} MB)!")

    # Live verification checks
    print("\n====================================================================")
    print("                SAMPLE INFERENCE VERIFICATION CHECKS                ")
    print("====================================================================")
    verification_samples = [
        "https://www.google.com",
        "https://en.wikipedia.org/wiki/Main_Page",
        "https://github.com/torvalds/linux",
        "br-icloud.com.br",
        "http://wallet-recovery.example.com/restore?seed=required",
        "https://paypal-verify-account.xyz/login"
    ]

    for sample in verification_samples:
        tokens = clean_url_tokens(sample)
        prob = pipeline.predict_proba([tokens])[0][1]
        verdict = "MALICIOUS (THREAT)" if prob >= 0.50 else "BENIGN (SAFE)"
        print(f" • '{sample[:52]:<52}' -> {verdict:<18} (Phish Prob: {round(prob*100, 1)}%)")

    print("====================================================================\n")
    return True

if __name__ == "__main__":
    train_and_export(max_samples=75000)

