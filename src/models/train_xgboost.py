import pandas as pd

# Splits the dataset into training and testing portions.
from sklearn.model_selection import train_test_split

# XGBClassifier is the classification model provided by XGBoost.
from xgboost import XGBClassifier

# These functions are used to evaluate the model.
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


# Location of our processed feature dataset.
DATA_FILE = "data/processed/url_features.csv"


# These are the 14 URL features used by all three baseline models.
# Keeping the same features makes our comparison fair.
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


def load_dataset():
    """
    Loads the feature dataset and separates:

    X = input URL features
    y = binary classification target

    Returns:
        X, y
    """

    # Read the CSV file into a pandas DataFrame.
    df = pd.read_csv(DATA_FILE)

    print(f"Total samples: {len(df)}")

    # Select only the 14 legitimate ML features.
    # We intentionally exclude URL, type, and the label columns.
    X = df[FEATURE_COLUMNS]

    # Binary target:
    # 0 = benign
    # 1 = malicious
    y = df["binary_label"]

    return X, y


def split_dataset(X, y):
    """
    Splits the dataset into training and testing sets.

    80% -> training
    20% -> testing

    stratify=y preserves the benign/malicious
    class distribution in both sets.
    """

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    return X_train, X_test, y_train, y_test


def train_model(X_train, y_train):
    """
    Creates and trains the XGBoost classifier.

    XGBoost builds decision trees sequentially.
    Each new tree attempts to improve the errors
    made by the previous trees.
    """

    # Create the XGBoost classification model.
    model = XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1
    )

    print("\nTraining XGBoost...")

    # Train the model using the training dataset.
    model.fit(X_train, y_train)

    return model


def evaluate_model(model, X_test, y_test):
    """
    Evaluates XGBoost on previously unseen test data.

    Calculates:
        Accuracy
        Precision
        Recall
        F1 score
        Classification report
        Confusion matrix
    """

    # Generate predictions for the unseen test dataset.
    y_pred = model.predict(X_test)

    # Calculate accuracy.
    accuracy = accuracy_score(y_test, y_pred)

    # Calculate precision for the malicious class.
    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0
    )

    # Calculate recall for the malicious class.
    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0
    )

    # Calculate F1 score.
    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0
    )

    print("\n==============================")
    print("XGBOOST RESULTS")
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


def main():
    """
    Runs the complete XGBoost training pipeline.

    Steps:
        1. Load dataset
        2. Select features and target
        3. Split dataset
        4. Train XGBoost
        5. Evaluate predictions
    """

    print("Loading feature dataset...")

    # Load features and target labels.
    X, y = load_dataset()

    print(f"Features: {X.shape[1]}")
    print(f"Samples: {X.shape[0]}")

    print("\nClass distribution:")
    print(y.value_counts())

    # Create training and testing datasets.
    X_train, X_test, y_train, y_test = split_dataset(X, y)

    print("\nDataset split:")
    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples: {len(X_test)}")

    # Train the XGBoost model.
    model = train_model(X_train, y_train)

    # Evaluate the trained model.
    evaluate_model(model, X_test, y_test)


# Run main() only when this Python file is executed directly.
if __name__ == "__main__":
    main()
