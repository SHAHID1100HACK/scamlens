"""Train the secondary text classifier on the UCI SMS Spam Collection (CC BY 4.0).
Dataset file: data/sms_spam/sms.tsv  (label<TAB>text). Source: archive.ics.uci.edu/dataset/228"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline
from app import config

rows = [l.rstrip("\n").split("\t", 1) for l in open(config.DATA_DIR / "sms_spam" / "sms.tsv", encoding="utf-8", errors="ignore") if "\t" in l]
y = [1 if r[0] == "spam" else 0 for r in rows]
X = [r[1] for r in rows]
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
pipe = Pipeline([
    ("f", FeatureUnion([
        ("w", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2)),
        ("c", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, min_df=3)),
    ])),
    ("lr", LogisticRegression(max_iter=2000, class_weight="balanced", C=4.0)),
])
pipe.fit(Xtr, ytr)
print(classification_report(yte, pipe.predict(Xte), target_names=["ham", "spam"], digits=3))
config.MODEL_DIR.mkdir(exist_ok=True)
joblib.dump(pipe, config.MODEL_DIR / "classifier.joblib")
print("saved", config.MODEL_DIR / "classifier.joblib")
