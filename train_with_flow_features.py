# train_with_flow_features.py
"""
Train a model using only the features that your flow sniffer actually generates.
"""
import os, time, joblib, warnings
warnings.filterwarnings("ignore")
import numpy as np, pandas as pd, matplotlib.pyplot as plt, seaborn as sns

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from imblearn.over_sampling import SMOTE

# ---------- SETTINGS ----------
DATA_PATH = "combined_dataset.csv"
ARTIFACT_DIR = "artifacts_simple"
os.makedirs(ARTIFACT_DIR, exist_ok=True)
RANDOM_STATE = 42
np.random.seed(RANDOM_STATE)

# Features that your flow sniffer actually generates (simplified)
FLOW_FEATURES = [
    'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts',
    'TotLen Bwd Pkts', 'Flow Byts/s', 'Flow Pkts/s',
    'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt',
    'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'ECE Flag Cnt'
]

# ---------- LOAD AND PREPARE DATA ----------
print("Loading dataset:", DATA_PATH)
df = pd.read_csv(DATA_PATH)
print("Original shape:", df.shape)

# Clean labels
df["Label"] = df["Label"].astype(str).str.upper().str.strip()
label_map = {"DD0S":"DDOS","D-DOS":"DDOS","D DOS":"DDOS","DDOS":"DDOS"}
df["Label"] = df["Label"].replace(label_map)
print("Label counts:", df["Label"].value_counts())

# Select only the features we know our flow sniffer generates
available_features = []
for feat in FLOW_FEATURES:
    if feat in df.columns:
        available_features.append(feat)
    else:
        print(f"⚠️ Warning: Feature '{feat}' not in dataset, skipping")

print(f"\nUsing {len(available_features)} available features:")
for feat in available_features:
    print(f"  - {feat}")

X = df[available_features]
y = df["Label"]

# Drop rows with missing values
X = X.dropna()
y = y.loc[X.index]

print(f"\nFinal dataset shape: {X.shape}")
print(f"Class distribution:\n{y.value_counts()}")

# ---------- ENCODE LABELS ----------
le = LabelEncoder()
y_encoded = le.fit_transform(y)
class_names = le.classes_
joblib.dump(le, os.path.join(ARTIFACT_DIR, "label_encoder.joblib"))
print(f"\nClasses: {class_names}")

# ---------- SPLIT ----------
X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.20, stratify=y_encoded, random_state=RANDOM_STATE
)
print(f"Train shape: {X_train.shape}, Test shape: {X_test.shape}")

# ---------- BALANCE TRAINING SET (SMOTE) ----------
print("\nApplying SMOTE...")
sm = SMOTE(random_state=RANDOM_STATE)
X_train_sm, y_train_sm = sm.fit_resample(X_train, y_train)
print(f"After SMOTE: {X_train_sm.shape}")

# ---------- SCALE ----------
scaler = StandardScaler()
X_train_sm_scl = scaler.fit_transform(X_train_sm)
X_test_scl = scaler.transform(X_test)
joblib.dump(scaler, os.path.join(ARTIFACT_DIR, "scaler.joblib"))
print("Scaler saved.")

# ---------- TRAIN SIMPLE RANDOM FOREST ----------
print("\n" + "="*50)
print("TRAINING SIMPLE RANDOM FOREST")
print("="*50)

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    random_state=RANDOM_STATE,
    n_jobs=-1
)

print("Training model...")
model.fit(X_train_sm_scl, y_train_sm)

# Evaluate
y_pred = model.predict(X_test_scl)
acc = accuracy_score(y_test, y_pred)
cr = classification_report(y_test, y_pred, target_names=class_names)
cm = confusion_matrix(y_test, y_pred)

print(f"\nAccuracy: {acc:.4f}")
print(f"\nClassification Report:\n{cr}")

# Save model
joblib.dump(model, os.path.join(ARTIFACT_DIR, "RandomForest.joblib"))
print("Model saved.")

# Save confusion matrix
plt.figure(figsize=(10,8))
sns.heatmap(cm, annot=True, fmt='d', xticklabels=class_names, yticklabels=class_names, cmap="Blues")
plt.title("RandomForest Confusion Matrix")
plt.tight_layout()
plt.savefig(os.path.join(ARTIFACT_DIR, "confusion_matrix.png"))
plt.close()

# Feature importance
feat_imp = pd.Series(model.feature_importances_, index=available_features).sort_values(ascending=False)
feat_imp.to_csv(os.path.join(ARTIFACT_DIR, "feature_importances.csv"))

plt.figure(figsize=(10,6))
feat_imp.plot(kind="barh")
plt.title("Feature Importances")
plt.tight_layout()
plt.savefig(os.path.join(ARTIFACT_DIR, "feature_importance.png"))
plt.close()

print("\n" + "="*50)
print("TRAINING COMPLETE")
print("="*50)
print(f"Features used: {len(available_features)}")
print(f"Test accuracy: {acc:.4f}")
print(f"Model saved to: {ARTIFACT_DIR}/")