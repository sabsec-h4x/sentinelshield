# ─────────────────────────────────────────────────────────────────
#  ml/anomaly_detector.py — Zero-Day Attack Detection using ML
#
#  WHAT IS ISOLATION FOREST?
#  Normal ML asks: "Does this look like attack pattern X?"
#  Isolation Forest asks: "Does this look NORMAL at all?"
#
#  It works by building random decision trees.
#  NORMAL requests are hard to isolate (they blend in with others)
#  ANOMALOUS requests are easy to isolate (they stand out)
#
#  WHY IS THIS POWERFUL?
#  Rules can only detect attacks they've SEEN BEFORE.
#  ML can detect attacks NO ONE HAS EVER SEEN — zero-days!
#
#  EXAMPLE:
#  Rule engine: "I don't recognize this payload — ALLOW it"
#  ML detector: "This payload looks nothing like normal traffic — FLAG it"
# ─────────────────────────────────────────────────────────────────

import os
import sys
import pickle
import numpy as np
from typing import Tuple

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Try to import sklearn — it's optional (graceful fallback if not installed)
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("⚠️  scikit-learn not found. ML detection disabled.")

MODEL_PATH  = os.path.join(os.path.dirname(__file__), "model.pkl")
SCALER_PATH = os.path.join(os.path.dirname(__file__), "scaler.pkl")


# ── Feature Extraction ────────────────────────────────────────────

def extract_features(request_data: dict) -> np.ndarray:
    """
    Convert a raw request into a numeric feature vector.

    ML models can't understand text — they only understand numbers.
    So we convert every property of a request into a number.

    FEATURES WE EXTRACT (15 total):
    1.  URL path length
    2.  Query string length
    3.  Body length
    4.  Number of query parameters
    5.  Special character count (', ", <, >, ;, |, `)
    6.  Encoded character count (%XX sequences)
    7.  Digit ratio (how many chars are numbers?)
    8.  Uppercase ratio
    9.  Unique char ratio (entropy indicator)
    10. Longest consecutive same char (AAAAAAA = fuzzing)
    11. Dot-dot count (../../ traversal indicator)
    12. SQL keyword count
    13. Script/HTML tag count
    14. Shell metacharacter count
    15. HTTP method encoded as number (GET=0, POST=1, etc.)
    """
    path    = str(request_data.get("path",  "") or "")
    query   = str(request_data.get("query", "") or "")
    body    = str(request_data.get("body",  "") or "")
    method  = str(request_data.get("method","GET") or "GET").upper()
    full    = path + " " + query + " " + body

    # Feature 1-3: Length features
    f1_path_len    = min(len(path),  2000) / 2000
    f2_query_len   = min(len(query), 2000) / 2000
    f3_body_len    = min(len(body),  5000) / 5000

    # Feature 4: Query parameter count
    param_count    = query.count("&") + (1 if query else 0)
    f4_param_count = min(param_count, 20) / 20

    # Feature 5: Special character density
    special_chars  = sum(full.count(c) for c in ["'", '"', "<", ">", ";", "|", "`", "\\"])
    f5_special     = min(special_chars, 50) / 50

    # Feature 6: URL encoding density (%XX)
    encoded_count  = full.count("%")
    f6_encoded     = min(encoded_count, 30) / 30

    # Feature 7: Digit ratio
    digits         = sum(1 for c in full if c.isdigit())
    f7_digit_ratio = digits / max(len(full), 1)

    # Feature 8: Uppercase ratio
    uppers         = sum(1 for c in full if c.isupper())
    f8_upper_ratio = uppers / max(len(full), 1)

    # Feature 9: Unique character ratio (low = repetitive = fuzzing)
    unique_chars   = len(set(full))
    f9_unique      = unique_chars / max(len(full), 1)

    # Feature 10: Longest run of same character (AAAAAAA = fuzzing/overflow attempt)
    max_run = 1
    cur_run = 1
    for i in range(1, len(full)):
        if full[i] == full[i-1]:
            cur_run += 1
            max_run = max(max_run, cur_run)
        else:
            cur_run = 1
    f10_max_run = min(max_run, 50) / 50

    # Feature 11: Directory traversal indicators
    dotdot_count   = full.count("..") + full.count("%2e%2e")
    f11_traversal  = min(dotdot_count, 10) / 10

    # Feature 12: SQL keyword density
    sql_keywords   = ["select", "union", "insert", "update", "delete",
                      "drop", "exec", "sleep", "benchmark", "having"]
    full_lower     = full.lower()
    sql_count      = sum(full_lower.count(kw) for kw in sql_keywords)
    f12_sql        = min(sql_count, 10) / 10

    # Feature 13: HTML/script indicators
    html_count     = full_lower.count("<script") + full_lower.count("onerror") + \
                     full_lower.count("javascript:") + full_lower.count("<iframe")
    f13_html       = min(html_count, 5) / 5

    # Feature 14: Shell metacharacter density
    shell_chars    = sum(full.count(c) for c in ["|", ";", "`", "$", "&&", "||"])
    f14_shell      = min(shell_chars, 10) / 10

    # Feature 15: HTTP method (encoded numerically)
    method_map     = {"GET": 0.0, "POST": 0.2, "PUT": 0.4,
                      "DELETE": 0.6, "PATCH": 0.8, "OPTIONS": 1.0}
    f15_method     = method_map.get(method, 0.5)

    return np.array([
        f1_path_len, f2_query_len, f3_body_len, f4_param_count,
        f5_special, f6_encoded, f7_digit_ratio, f8_upper_ratio,
        f9_unique, f10_max_run, f11_traversal, f12_sql,
        f13_html, f14_shell, f15_method
    ], dtype=np.float32)


# ── Anomaly Detector Class ────────────────────────────────────────

class AnomalyDetector:
    """
    ML-based anomaly detector using Isolation Forest.

    USAGE:
        detector = AnomalyDetector()
        detector.train()          # Train on normal traffic samples
        score, is_anomaly = detector.predict(request_data)
    """

    def __init__(self):
        self.model   = None
        self.scaler  = None
        self.trained = False
        self._load_or_train()

    def _load_or_train(self):
        """Load existing model or train a new one from scratch."""
        if not ML_AVAILABLE:
            return

        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            try:
                with open(MODEL_PATH,  "rb") as f: self.model  = pickle.load(f)
                with open(SCALER_PATH, "rb") as f: self.scaler = pickle.load(f)
                self.trained = True
                print("✅ ML model loaded from disk")
                return
            except Exception as e:
                print(f"⚠️  Could not load ML model: {e}. Retraining...")

        # No saved model — train from scratch
        self.train()

    def train(self, extra_samples: list = None):
        """
        Train the Isolation Forest on normal traffic patterns.

        We generate synthetic "normal" traffic samples to teach
        the model what legitimate requests look like.
        In production, you'd use real historical traffic instead.
        """
        if not ML_AVAILABLE:
            print("⚠️  ML not available — skipping training")
            return

        print("🤖 Training ML anomaly detector...")

        # Generate normal traffic samples
        normal_samples = self._generate_normal_samples(500)

        # Add any extra real samples if provided
        if extra_samples:
            for s in extra_samples:
                normal_samples.append(extract_features(s))

        X = np.array(normal_samples)

        # Scale features to same range (important for ML)
        self.scaler = StandardScaler()
        X_scaled    = self.scaler.fit_transform(X)

        # Train Isolation Forest
        # contamination = expected % of anomalies (5% here)
        self.model = IsolationForest(
            n_estimators  = 100,    # number of trees (more = more accurate but slower)
            contamination = 0.05,   # 5% of training data expected to be anomalous
            random_state  = 42,     # for reproducibility
            max_features  = 0.8,    # use 80% of features per tree (prevents overfitting)
        )
        self.model.fit(X_scaled)
        self.trained = True

        # Save to disk so we don't retrain every restart
        with open(MODEL_PATH,  "wb") as f: pickle.dump(self.model,  f)
        with open(SCALER_PATH, "wb") as f: pickle.dump(self.scaler, f)

        print(f"✅ ML model trained on {len(normal_samples)} samples & saved")

    def predict(self, request_data: dict) -> Tuple[float, bool]:
        """
        Predict whether a request is anomalous.

        Returns:
            (anomaly_score, is_anomaly)
            anomaly_score: 0.0 (normal) to 1.0 (very anomalous)
            is_anomaly:    True if this looks like a zero-day attack
        """
        if not ML_AVAILABLE or not self.trained:
            return 0.0, False

        try:
            features  = extract_features(request_data).reshape(1, -1)
            scaled    = self.scaler.transform(features)

            # score_samples returns negative values:
            # More negative = more anomalous
            # We flip and normalize to 0-1 range
            raw_score   = self.model.score_samples(scaled)[0]
            # Typical range is about -0.8 to -0.1
            # Normalize: -0.8 → 1.0 (very anomalous), -0.1 → 0.0 (normal)
            norm_score  = max(0.0, min(1.0, (-raw_score - 0.1) / 0.7))

            # Isolation Forest predict: -1 = anomaly, 1 = normal
            prediction  = self.model.predict(scaled)[0]
            is_anomaly  = (prediction == -1) and (norm_score > 0.3)

            return round(float(norm_score), 3), is_anomaly

        except Exception as e:
            print(f"⚠️  ML prediction error: {e}")
            return 0.0, False

    def _generate_normal_samples(self, count: int) -> list:
        """
        Generate synthetic normal HTTP request feature vectors.
        These teach the model what legitimate traffic looks like.
        """
        import random
        samples = []

        normal_templates = [
            # Normal GET requests
            {"path": "/products", "query": "id=42&page=1", "body": "", "method": "GET"},
            {"path": "/search",   "query": "q=shoes&sort=price", "body": "", "method": "GET"},
            {"path": "/user",     "query": "id=100",  "body": "", "method": "GET"},
            {"path": "/api/v1/items", "query": "limit=20&offset=0", "body": "", "method": "GET"},
            # Normal POST requests
            {"path": "/login",    "query": "", "body": "username=john&password=pass123", "method": "POST"},
            {"path": "/register", "query": "", "body": "email=user@example.com&name=John", "method": "POST"},
            {"path": "/api/cart", "query": "", "body": '{"item_id": 5, "qty": 2}', "method": "POST"},
            {"path": "/contact",  "query": "", "body": "name=Alice&message=Hello+world", "method": "POST"},
        ]

        for _ in range(count):
            template = random.choice(normal_templates).copy()

            # Add slight random variation to make training robust
            if random.random() < 0.3:
                template["query"] += f"&page={random.randint(1, 100)}"
            if random.random() < 0.2:
                template["path"] += f"/{random.randint(1, 999)}"

            samples.append(extract_features(template))

        return samples


# ── Singleton Instance ────────────────────────────────────────────
anomaly_detector = AnomalyDetector()
