import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


DATA_FILE = "data/processed/url_features.csv"


FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "dot_count",
    "hyphen_count",
    "digit_count",
    "special_char_count",
    "subdomain_count",
    "contains_ip",
    "uses_https",
    "contains_at",
    "contains_double_slash",
    "suspicious_keyword_count"
]


def main():

    print("Loading feature dataset...")

    df = pd.read_csv(DATA_FILE)

    print(f"Total samples: {len(df)}")

    # -----------------------------
    # Prepare features
    # -----------------------------

    X = df[FEATURE_COLUMNS]

    # Binary classification:
    # 0 = benign
    # 1 = malicious
    y = df["binary_label"]

    print(f"Features: {X.shape[1]}")
    print(f"Samples: {X.shape[0]}")

    print("\nClass distribution:")
    print(y.value_counts())

    # -----------------------------
    # Train/Test Split
    # -----------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print("\nDataset split:")
    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples: {len(X_test)}")

    # -----------------------------
    # Logistic Regression
    # -----------------------------

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42
        ))
    ])

    print("\nTraining Logistic Regression...")

    model.fit(X_train, y_train)

    # -----------------------------
    # Predictions
    # -----------------------------

    y_pred = model.predict(X_test)

    # -----------------------------
    # Evaluation
    # -----------------------------

    accuracy = accuracy_score(y_test, y_pred)

    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0
    )

    print("\n==============================")
    print("LOGISTIC REGRESSION RESULTS")
    print("==============================")

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            y_pred,
            target_names=["Benign", "Malicious"],
            zero_division=0
        )
    )

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))


if __name__ == "__main__":
    main()
