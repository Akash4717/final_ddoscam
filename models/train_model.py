"""
AI-Powered DDoS Detection Model Training
Trains Random Forest and Isolation Forest models on synthetic traffic data
Generates full evaluation outputs for report
"""

# ================= FIX GUI ISSUES =================
import matplotlib
matplotlib.use("Agg")   # Prevent Tkinter errors

# ================= IMPORTS =================
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    roc_curve,
    auc,
    precision_recall_curve
)
from sklearn.preprocessing import StandardScaler
import joblib
import os
import json
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns

# ================= DIRECTORIES =================
os.makedirs("saved_models", exist_ok=True)
os.makedirs("saved_models/plots", exist_ok=True)
os.makedirs("../data/processed", exist_ok=True)

# ================= DATA GENERATION =================
def generate_synthetic_data(n_samples=50000):

    print("[*] Generating synthetic traffic data...")

    n_normal = int(n_samples * 0.7)
    n_http = int(n_samples * 0.15)
    n_syn = int(n_samples * 0.10)
    n_udp = n_samples - n_normal - n_http - n_syn

    def block(n, pps, bps, src, ports, pkt, var, dur, syn, rst, ack, rate, ent, label):
        return pd.DataFrame({
            "packets_per_sec": np.random.normal(*pps, n),
            "bytes_per_sec": np.random.normal(*bps, n),
            "unique_src_ips": np.random.randint(*src, n),
            "unique_dst_ports": np.random.randint(*ports, n),
            "avg_packet_size": np.random.normal(*pkt, n),
            "packet_size_variance": np.random.normal(*var, n),
            "flow_duration": np.random.normal(*dur, n),
            "syn_count": np.random.randint(*syn, n),
            "rst_count": np.random.randint(*rst, n),
            "ack_count": np.random.randint(*ack, n),
            "connection_rate": np.random.normal(*rate, n),
            "src_ip_entropy": np.random.uniform(*ent, n),
            "label": label
        })

    df = pd.concat([
        block(n_normal,(100,20),(50000,10000),(1,10),(1,5),(500,100),(100,30),(5,2),(0,10),(0,5),(0,100),(10,3),(2,4),0),
        block(n_http,(10000,2000),(5e6,1e6),(100,1000),(1,3),(300,50),(50,20),(1,0.5),(1000,10000),(0,100),(1000,10000),(1000,200),(5,8),1),
        block(n_syn,(15000,3000),(1e6,2e5),(500,2000),(1,5),(60,10),(10,5),(0.5,0.2),(10000,50000),(0,50),(0,100),(5000,1000),(6,9),1),
        block(n_udp,(20000,5000),(1e7,2e6),(200,1500),(10,100),(1000,200),(300,100),(0.3,0.1),(0,10),(0,10),(0,50),(3000,500),(4,7),1)
    ]).sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"[✓] Generated {len(df)} samples")
    return df

# ================= PLOT FUNCTIONS =================
def plot_confusion_matrix_graph(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(6,5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["Normal","Attack"],
                yticklabels=["Normal","Attack"])
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Confusion Matrix - Random Forest")
    plt.tight_layout()
    plt.savefig("saved_models/plots/confusion_matrix.png")
    plt.close()

def plot_classification_report_graph(y_true, y_pred):
    report = classification_report(y_true, y_pred, output_dict=True)
    df = pd.DataFrame(report).transpose()

    # Correct class labels
    df = df.loc[["0", "1"], ["precision", "recall", "f1-score"]]

    df.plot(kind="bar", figsize=(7,5))
    plt.ylim(0,1)
    plt.ylabel("Score")
    plt.title("Classification Report Metrics")
    plt.grid(axis="y")
    plt.tight_layout()
    plt.savefig("saved_models/plots/classification_report.png")
    plt.close()

def plot_roc_curve_graph(y_true, y_prob):
    fpr, tpr, _ = roc_curve(y_true, y_prob)
    roc_auc = auc(fpr, tpr)
    plt.figure(figsize=(6,5))
    plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.2f}")
    plt.plot([0,1],[0,1],'--')
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve - Random Forest")
    plt.legend()
    plt.grid()
    plt.tight_layout()
    plt.savefig("saved_models/plots/roc_curve.png")
    plt.close()

def plot_precision_recall_curve_graph(y_true, y_prob):
    precision, recall, _ = precision_recall_curve(y_true, y_prob)
    plt.figure(figsize=(6,5))
    plt.plot(recall, precision)
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("Precision–Recall Curve - Random Forest")
    plt.grid()
    plt.tight_layout()
    plt.savefig("saved_models/plots/precision_recall_curve.png")
    plt.close()

# ================= TRAINING =================
def train_models(df):

    X = df.drop("label", axis=1)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, stratify=y, random_state=42
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)

    rf_predictions = rf_model.predict(X_test)
    rf_probabilities = rf_model.predict_proba(X_test)[:,1]

    iso_model = IsolationForest(contamination=0.3, random_state=42)
    iso_model.fit(X_train)
    iso_predictions = np.where(iso_model.predict(X_test) == -1, 1, 0)

    ensemble_predictions = np.where((rf_predictions + iso_predictions) >= 1, 1, 0)

    # ===== PLOTS =====
    plot_confusion_matrix_graph(y_test, rf_predictions)
    plot_classification_report_graph(y_test, rf_predictions)
    plot_roc_curve_graph(y_test, rf_probabilities)
    plot_precision_recall_curve_graph(y_test, rf_probabilities)

    # ===== PRINT METRICS =====
    print("\nClassification Report:")
    print(classification_report(y_test, rf_predictions, target_names=["Normal","Attack"]))
    print("Confusion Matrix:\n", confusion_matrix(y_test, rf_predictions))

    # ===== SAVE MODELS =====
    joblib.dump(rf_model, "saved_models/random_forest_model.pkl")
    joblib.dump(iso_model, "saved_models/isolation_forest_model.pkl")
    joblib.dump(scaler, "saved_models/scaler.pkl")

    metadata = {
        "training_date": datetime.now().isoformat(),
        "rf_accuracy": accuracy_score(y_test, rf_predictions),
        "iso_accuracy": accuracy_score(y_test, iso_predictions),
        "ensemble_accuracy": accuracy_score(y_test, ensemble_predictions)
    }

    with open("saved_models/metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    return metadata

# ================= MAIN =================
def main():
    print("="*60)
    print("AI-POWERED DDoS DETECTION - MODEL TRAINING")
    print("="*60)

    df = generate_synthetic_data()
    df.to_csv("../data/processed/training_data.csv", index=False)

    metadata = train_models(df)

    print("\nTRAINING COMPLETE")
    print(f"Final Ensemble Accuracy: {metadata['ensemble_accuracy']*100:.2f}%")

if __name__ == "__main__":
    main()
